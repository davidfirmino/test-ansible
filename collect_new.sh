#!/usr/bin/env bash
#
# collect_san_debug_v3.37.sh
#
# End-to-end SAN debug collector for a single Linux host and one dm device.
# - Captures host I/O (biosnoop, biolatency, iostat)
# - Captures CPU, network, TCP stack, NIC counters
# - Queries VictoriaMetrics for Pure FlashArray host + volume latency and IO size
# - Packages everything into a single ZIP file
#
# Run as root.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

#######################################
# DEFAULT CONFIG (can be overridden by CLI)
#######################################

DEV="dm-8"                                 # dm device (without /dev/)
IFACES="ens1f1 ens2f1"                     # space-separated NICs
DURATION=300                               # seconds
INTERVAL=1                                 # iostat/mpstat/sar interval
SS_INTERVAL=5                              # ss -ti sampling interval
OUTDIR="/var/log/san_debug"

VM_URL="https://vmselect.is.adyen.com/select/0/prometheus"
PURE_ARRAY_NAME="FlashArray-01"            # e.g. pure4-nlzwo1o
PURE_HOST_NAME="$(hostname -s)"            # Pure host label
PURE_VOLUME_NAME=""                        # Pure volume name label

ENABLE_BIOSNOOP="${ENABLE_BIOSNOOP:-1}"    # 1 = enabled, 0 = disabled

#######################################
# CLI PARSING
#######################################

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --hostdm <dm-N>            Device mapper name (default: dm-8)
  --ifaces "eth0 eth1"       Space-separated list of NICs (default: "ens1f1 ens2f1")
  --duration <seconds>       Total duration in seconds (default: 300)
  --interval <seconds>       Sampling interval for iostat/mpstat/sar (default: 1)
  --ss-interval <seconds>    Sampling interval for ss -ti (default: 5)
  --outdir <path>            Output directory (default: /var/log/san_debug)
  --vm-url <url>             VictoriaMetrics URL (default: ${VM_URL})
  --pure-array <name>        Pure array base name (e.g. pure4-nlzwo1o)
  --pure-host <name>         Pure host name label (default: \$(hostname -s))
  --pure-volume <name>       Pure volume name label (optional)
  --disable-biosnoop         Disable biosnoop capture (ENABLE_BIOSNOOP=0)

Example:
  $0 \\
    --hostdm dm-8 \\
    --ifaces "ens1f1 ens2f1" \\
    --duration 300 \\
    --pure-host dblive14066-a \\
    --pure-volume dblive14066-a_pgsql \\
    --pure-array pure4-nlzwo1o
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostdm)
      DEV="$2"; shift 2 ;;
    --ifaces)
      IFACES="$2"; shift 2 ;;
    --duration)
      DURATION="$2"; shift 2 ;;
    --interval)
      INTERVAL="$2"; shift 2 ;;
    --ss-interval)
      SS_INTERVAL="$2"; shift 2 ;;
    --outdir)
      OUTDIR="$2"; shift 2 ;;
    --vm-url)
      VM_URL="$2"; shift 2 ;;
    --pure-array)
      PURE_ARRAY_NAME="$2"; shift 2 ;;
    --pure-host)
      PURE_HOST_NAME="$2"; shift 2 ;;
    --pure-volume)
      PURE_VOLUME_NAME="$2"; shift 2 ;;
    --disable-biosnoop)
      ENABLE_BIOSNOOP=0; shift 1 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1 ;;
  esac
done

#######################################
# PREPARATION
#######################################

COUNT=$(( DURATION / INTERVAL ))
mkdir -p "$OUTDIR"

TS="$(date +%F_%H%M%S)"
PREFIX="${OUTDIR}/${TS}_${DEV}"

# Locate BCC tools
if [ -f /usr/share/bcc/tools/biosnoop ]; then
    BIOSNOOP_BIN="/usr/share/bcc/tools/biosnoop"
    BIOLAT_BIN="/usr/share/bcc/tools/biolatency"
elif [ -f /usr/sbin/biosnoop-bpfcc ]; then
    BIOSNOOP_BIN="/usr/sbin/biosnoop-bpfcc"
    BIOLAT_BIN="/usr/sbin/biolatency-bpfcc"
else
    BIOSNOOP_BIN="biosnoop"
    BIOLAT_BIN="biolatency"
fi

# nic_status.sh removido da lista abaixo
REQUIRED_CMDS="jq curl sar mpstat zip iostat ss ethtool"
for cmd in $REQUIRED_CMDS; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: Command '$cmd' is missing. Please install it."
        exit 1
    fi
done

echo "=== SAN Debug Collection v3.37 ==="
echo "  Device            : $DEV"
echo "  Interfaces        : $IFACES"
echo "  Duration          : ${DURATION}s (interval=${INTERVAL}s, ss-interval=${SS_INTERVAL}s)"
echo "  VM URL            : $VM_URL"
echo "  Array Name        : $PURE_ARRAY_NAME"
echo "---------------------------------"
echo "  Target Pure Host  : $PURE_HOST_NAME"
echo "  Target Pure Volume: ${PURE_VOLUME_NAME:-<none>}"
echo "---------------------------------"
echo "  ENABLE_BIOSNOOP   : $ENABLE_BIOSNOOP"
echo "  Output dir        : $OUTDIR"
echo "=================================="

START_TS="$(date +%s)"

#######################################
# CLEANUP TRAP
#######################################
cleanup() {
    tput cnorm 2>/dev/null || true
    echo ""
    echo "[!] Stopping collectors..."
    pkill -P $$ 2>/dev/null || true
    wait 2>/dev/null || true
    echo "[!] Done."
}
trap cleanup EXIT INT TERM

#######################################
# INITIAL SNAPSHOTS
#######################################

echo "[1/9] Capturing initial state..."

ss -tnie '( dport = :3260 or sport = :3260 )' > "${PREFIX}_ss_start.log" 2>/dev/null || true
multipath -ll "$DEV" > "${PREFIX}_multipath_topology.log" 2>/dev/null || true
cat /proc/net/snmp > "${PREFIX}_snmp_start.log"
grep '^TcpExt:' /proc/net/netstat > "${PREFIX}_tcpext_start.log" 2>/dev/null || true

for iface in $IFACES; do
    ethtool -S "$iface" > "${PREFIX}_ethtool_start_${iface}.log" 2>/dev/null || true
done

# Bloco [2/10] de descoberta de switch removido pois dependia do nic_status.sh

#######################################
# BACKGROUND COLLECTION
#######################################

echo "[2/9] Starting iostat..."
iostat -x -k -t "$INTERVAL" "$COUNT" "/dev/$DEV" > "${PREFIX}_iostat_${DEV}.log" &

echo "[3/9] Starting mpstat..."
mpstat -P ALL "$INTERVAL" "$COUNT" > "${PREFIX}_mpstat.log" &

echo "[4/9] Starting sar..."
sar -n DEV "$INTERVAL" "$COUNT" > "${PREFIX}_sar_net.log" &

echo "[5/9] Starting biolatency..."
$BIOLAT_BIN -Q -d "$DEV" "$INTERVAL" "$COUNT" > "${PREFIX}_biolatency_${DEV}.log" 2>/dev/null &

echo "[6/9] Starting biosnoop (if enabled)..."
PID_BIOSNOOP=""
if [[ "$ENABLE_BIOSNOOP" -eq 1 ]]; then
    $BIOSNOOP_BIN -Q -d "$DEV" > "${PREFIX}_biosnoop_raw_${DEV}.log" 2>/dev/null &
    PID_BIOSNOOP=$!
fi

echo "[*] Starting ss -ti timeline..."
{
    while true; do
        date "+%F %T" >> "${PREFIX}_ss_timeline.log"
        ss -ti '( dport = :3260 or sport = :3260 )' >> "${PREFIX}_ss_timeline.log" 2>/dev/null || true
        echo "----" >> "${PREFIX}_ss_timeline.log"
        sleep "$SS_INTERVAL"
    done
} &
PID_SS_TIMELINE=$!

#######################################
# TIMER LOOP
#######################################

echo "[*] Collection in progress. Press Ctrl+C to stop early."
tput civis 2>/dev/null || true
for ((i=1; i<=DURATION; i++)); do
    printf "\r[Running] %-3s seconds remaining..." "$((DURATION - i))"
    sleep 1
done
tput cnorm 2>/dev/null || true
echo ""

#######################################
# FINAL SNAPSHOTS
#######################################

echo "[7/9] Capturing final state..."

END_TS="$(date +%s)"
{
    echo "START_TS=${START_TS}"
    echo "END_TS=${END_TS}"
    echo "PURE_HOST_NAME=${PURE_HOST_NAME}"
    echo "PURE_VOLUME_NAME=${PURE_VOLUME_NAME}"
} > "${PREFIX}_time_window.txt"

if [[ -n "${PID_BIOSNOOP:-}" ]]; then
    kill "$PID_BIOSNOOP" 2>/dev/null || true
fi
kill "$PID_SS_TIMELINE" 2>/dev/null || true

ss -tnie '( dport = :3260 or sport = :3260 )' > "${PREFIX}_ss_end.log" 2>/dev/null || true
cat /proc/net/snmp > "${PREFIX}_snmp_end.log"
grep '^TcpExt:' /proc/net/netstat > "${PREFIX}_tcpext_end.log" 2>/dev/null || true

for iface in $IFACES; do
    ethtool -S "$iface" > "${PREFIX}_ethtool_end_${iface}.log" 2>/dev/null || true
    echo "--- Error Diff for $iface ---" >> "${PREFIX}_ethtool_diff_errors.txt"
    if [ -s "${PREFIX}_ethtool_start_${iface}.log" ] && [ -s "${PREFIX}_ethtool_end_${iface}.log" ]; then
        diff "${PREFIX}_ethtool_start_${iface}.log" "${PREFIX}_ethtool_end_${iface}.log" \
            | grep -E "drop|err|fail|crc|fifo" >> "${PREFIX}_ethtool_diff_errors.txt" \
            || echo "Clean." >> "${PREFIX}_ethtool_diff_errors.txt"
    fi
done

if [ -s "${PREFIX}_tcpext_start.log" ] && [ -s "${PREFIX}_tcpext_end.log" ]; then
    echo "--- TcpExt Diff ---" > "${PREFIX}_tcpext_diff.log"
    diff "${PREFIX}_tcpext_start.log" "${PREFIX}_tcpext_end.log" >> "${PREFIX}_tcpext_diff.log" || true
fi

#######################################
# VICTORIAMETRICS QUERIES
#######################################

echo "[8/9] Querying VictoriaMetrics (Pure host & volume metrics)..."

build_weighted_latency_query_host() {
    local LAT_DIM="$1"
    local IOPS_DIM="$2"
    cat <<EOF
(
  sum by (realhostname, host) (
    sum_over_time(
      (
        purefa_host_performance_latency_usec{
          realhostname=~"${PURE_ARRAY_NAME}.*",
          host="${PURE_HOST_NAME}",
          dimension="${LAT_DIM}"
        }
        * on (realhostname, host) group_left
        purefa_host_performance_throughput_iops{
          realhostname=~"${PURE_ARRAY_NAME}.*",
          host="${PURE_HOST_NAME}",
          dimension="${IOPS_DIM}"
        }
      )[5m:30s]
    )
  )
  /
  sum by (realhostname, host) (
    sum_over_time(
      purefa_host_performance_throughput_iops{
        realhostname=~"${PURE_ARRAY_NAME}.*",
        host="${PURE_HOST_NAME}",
        dimension="${IOPS_DIM}"
      }[5m:30s]
    )
  )
) / 1000
EOF
}

build_weighted_latency_query_vol() {
    local LAT_DIM="$1"
    local IOPS_DIM="$2"
    cat <<EOF
(
  sum by (realhostname, name) (
    sum_over_time(
      (
        purefa_volume_performance_latency_usec{
          realhostname=~"${PURE_ARRAY_NAME}.*",
          name="${PURE_VOLUME_NAME}",
          dimension="${LAT_DIM}"
        }
        * on (realhostname, name) group_left
        purefa_volume_performance_throughput_iops{
          realhostname=~"${PURE_ARRAY_NAME}.*",
          name="${PURE_VOLUME_NAME}",
          dimension="${IOPS_DIM}"
        }
      )[5m:30s]
    )
  )
  /
  sum by (realhostname, name) (
    sum_over_time(
      purefa_volume_performance_throughput_iops{
        realhostname=~"${PURE_ARRAY_NAME}.*",
        name="${PURE_VOLUME_NAME}",
        dimension="${IOPS_DIM}"
      }[5m:30s]
    )
  )
) / 1000
EOF
}

fetch_pure_host_latency() {
    local LAT_DIM="$1"
    local IOPS_DIM="$2"
    local OUTFILE="$3"

    local QUERY
    QUERY="$(build_weighted_latency_query_host "$LAT_DIM" "$IOPS_DIM")"

    curl -k -f -s -G \
        --data-urlencode "query=${QUERY}" \
        --data-urlencode "time=${END_TS}" \
        "${VM_URL}/api/v1/query" \
        | jq '.' > "$OUTFILE" || echo "Error fetching Pure host latency metric (${LAT_DIM}/${IOPS_DIM})"
}

fetch_pure_vol_latency() {
    local LAT_DIM="$1"
    local IOPS_DIM="$2"
    local OUTFILE="$3"

    if [[ -z "${PURE_VOLUME_NAME}" ]]; then
        return
    fi

    local QUERY
    QUERY="$(build_weighted_latency_query_vol "$LAT_DIM" "$IOPS_DIM")"

    curl -k -f -s -G \
        --data-urlencode "query=${QUERY}" \
        --data-urlencode "time=${END_TS}" \
        "${VM_URL}/api/v1/query" \
        | jq '.' > "$OUTFILE" || echo "Error fetching Pure volume latency metric (${LAT_DIM}/${IOPS_DIM})"
}

fetch_pure_host_iosize() {
    local DIM="$1"
    local OUTFILE="$2"

    local QUERY="purefa_host_performance_average_bytes{realhostname=~\"${PURE_ARRAY_NAME}.*\", host=\"${PURE_HOST_NAME}\", dimension=\"${DIM}\"}"

    curl -k -f -s -G \
        --data-urlencode "query=${QUERY}" \
        --data-urlencode "time=${END_TS}" \
        "${VM_URL}/api/v1/query" \
        | jq '.' > "$OUTFILE" || echo "Error fetching Pure host IO size metric (${DIM})"
}

fetch_pure_vol_iosize() {
    local DIM="$1"
    local OUTFILE="$2"

    if [[ -z "${PURE_VOLUME_NAME}" ]]; then
        return
    fi

    local QUERY="purefa_volume_performance_average_bytes{realhostname=~\"${PURE_ARRAY_NAME}.*\", name=\"${PURE_VOLUME_NAME}\", dimension=\"${DIM}\"}"

    curl -k -f -s -G \
        --data-urlencode "query=${QUERY}" \
        --data-urlencode "time=${END_TS}" \
        "${VM_URL}/api/v1/query" \
        | jq '.' > "$OUTFILE" || echo "Error fetching Pure volume IO size metric (${DIM})"
}

echo "  -> Fetching Pure host-level metrics for host=${PURE_HOST_NAME} ..."
fetch_pure_host_latency "san_usec_per_read_op"   "reads_per_sec"  "${PREFIX}_vm_host_san_read_ms.json"
fetch_pure_host_latency "san_usec_per_write_op"  "writes_per_sec" "${PREFIX}_vm_host_san_write_ms.json"
fetch_pure_host_latency "service_usec_per_read_op"  "reads_per_sec"  "${PREFIX}_vm_host_service_read_ms.json"
fetch_pure_host_latency "service_usec_per_write_op" "writes_per_sec" "${PREFIX}_vm_host_service_write_ms.json"
fetch_pure_host_latency "queue_usec_per_read_op"    "reads_per_sec"  "${PREFIX}_vm_host_queue_read_ms.json"
fetch_pure_host_latency "queue_usec_per_write_op"   "writes_per_sec" "${PREFIX}_vm_host_queue_write_ms.json"

fetch_pure_host_iosize "bytes_per_read"  "${PREFIX}_vm_host_iosize_read_bytes.json"
fetch_pure_host_iosize "bytes_per_write" "${PREFIX}_vm_host_iosize_write_bytes.json"

if [[ -n "${PURE_VOLUME_NAME}" ]]; then
    echo "  -> Fetching Pure volume-level metrics for volume=${PURE_VOLUME_NAME} ..."
    fetch_pure_vol_latency "san_usec_per_read_op"   "reads_per_sec"  "${PREFIX}_vm_vol_san_read_ms.json"
    fetch_pure_vol_latency "san_usec_per_write_op"  "writes_per_sec" "${PREFIX}_vm_vol_san_write_ms.json"
    fetch_pure_vol_latency "service_usec_per_read_op"  "reads_per_sec"  "${PREFIX}_vm_vol_service_read_ms.json"
    fetch_pure_vol_latency "service_usec_per_write_op" "writes_per_sec" "${PREFIX}_vm_vol_service_write_ms.json"
    fetch_pure_vol_latency "queue_usec_per_read_op"    "reads_per_sec"  "${PREFIX}_vm_vol_queue_read_ms.json"
    fetch_pure_vol_latency "queue_usec_per_write_op"   "writes_per_sec" "${PREFIX}_vm_vol_queue_write_ms.json"

    fetch_pure_vol_iosize "bytes_per_read"  "${PREFIX}_vm_vol_iosize_read_bytes.json"
    fetch_pure_vol_iosize "bytes_per_write" "${PREFIX}_vm_vol_iosize_write_bytes.json"
fi

# Queries de Switch removidas pois dependiam da descoberta inicial do nic_status.sh

#######################################
# BIOSNOOP POST-PROCESSING
#######################################

echo "[*] Processing biosnoop tail..."
if [ -s "${PREFIX}_biosnoop_raw_${DEV}.log" ]; then
    awk 'BEGIN{
             OFS="\t";
             print "WALL_TIME","TIME(s)","COMM","PID","DISK","T","SECTOR","BYTES","QUE(ms)","LAT(ms)";
         }
         NR>1{
             print strftime("%H:%M:%S"),$0;
         }' \
      "${PREFIX}_biosnoop_raw_${DEV}.log" > "${PREFIX}_biosnoop_tail_${DEV}.log" 2>/dev/null || true
else
    echo "Info: biosnoop log is empty."
fi

#######################################
# QUICK SUMMARY (Bash)
#######################################

echo
echo "===== SAN DEBUG QUICK SUMMARY (v3.37) ====="

TOTAL_IOS=0
if [ -s "${PREFIX}_biosnoop_raw_${DEV}.log" ]; then
    TOTAL_IOS=$(awk 'NR>1{c++}END{print c+0}' "${PREFIX}_biosnoop_raw_${DEV}.log")
fi

VM_HOST_LABEL="N/A"
HOST_SAN_READ="N/A"
HOST_SAN_WRITE="N/A"
HOST_IO_READ="N/A"
HOST_IO_WRITE="N/A"

if [ -s "${PREFIX}_vm_host_san_read_ms.json" ]; then
    VM_HOST_LABEL=$(jq -r '.data.result[0].metric.host // "N/A"' "${PREFIX}_vm_host_san_read_ms.json" 2>/dev/null || echo "N/A")
    HOST_SAN_READ=$(jq -r '.data.result[0].value[1] // "N/A"' "${PREFIX}_vm_host_san_read_ms.json" 2>/dev/null || echo "N/A")
fi
if [ -s "${PREFIX}_vm_host_san_write_ms.json" ]; then
    HOST_SAN_WRITE=$(jq -r '.data.result[0].value[1] // "N/A"' "${PREFIX}_vm_host_san_write_ms.json" 2>/dev/null || echo "N/A")
fi
if [ -s "${PREFIX}_vm_host_iosize_read_bytes.json" ]; then
    HOST_IO_READ=$(jq -r '.data.result[0].value[1] // "N/A"' "${PREFIX}_vm_host_iosize_read_bytes.json" 2>/dev/null || echo "N/A")
fi
if [ -s "${PREFIX}_vm_host_iosize_write_bytes.json" ]; then
    HOST_IO_WRITE=$(jq -r '.data.result[0].value[1] // "N/A"' "${PREFIX}_vm_host_iosize_write_bytes.json" 2>/dev/null || echo "N/A")
fi

VOL_SAN_READ="N/A"
VOL_SAN_WRITE="N/A"
VOL_IO_READ="N/A"
VOL_IO_WRITE="N/A"

if [[ -n "${PURE_VOLUME_NAME}" ]]; then
    if [ -s "${PREFIX}_vm_vol_san_read_ms.json" ]; then
        VOL_SAN_READ=$(jq -r '.data.result[0].value[1] // "N/A"' "${PREFIX}_vm_vol_san_read_ms.json" 2>/dev/null || echo "N/A")
    fi
    if [ -s "${PREFIX}_vm_vol_san_write_ms.json" ]; then
        VOL_SAN_WRITE=$(jq -r '.data.result[0].value[1] // "N/A"' "${PREFIX}_vm_vol_san_write_ms.json" 2>/dev/null || echo "N/A")
    fi
    if [ -s "${PREFIX}_vm_vol_iosize_read_bytes.json" ]; then
        VOL_IO_READ=$(jq -r '.data.result[0].value[1] // "N/A"' "${PREFIX}_vm_vol_iosize_read_bytes.json" 2>/dev/null || echo "N/A")
    fi
    if [ -s "${PREFIX}_vm_vol_iosize_write_bytes.json" ]; then
        VOL_IO_WRITE=$(jq -r '.data.result[0].value[1] // "N/A"' "${PREFIX}_vm_vol_iosize_write_bytes.json" 2>/dev/null || echo "N/A")
    fi
fi

TIME_STR_START="$(date -d @"$START_TS" 2>/dev/null || date -r "$START_TS" 2>/dev/null)"
TIME_STR_END="$(date -d @"$END_TS" 2>/dev/null || date -r "$END_TS" 2>/dev/null)"
DUR=$(( END_TS - START_TS ))

echo "Time window : ${TIME_STR_START} -> ${TIME_STR_END} (${DUR}s)"
echo "Device      : $DEV"
echo "Total IOs   : $TOTAL_IOS"
echo "Pure Host   : $VM_HOST_LABEL"
echo "Host SAN    : read=${HOST_SAN_READ} ms, write=${HOST_SAN_WRITE} ms"
echo "Host IO Size: read=${HOST_IO_READ} B, write=${HOST_IO_WRITE} B"
if [[ -n "${PURE_VOLUME_NAME}" ]]; then
  echo "Volume      : ${PURE_VOLUME_NAME}"
  echo "Vol SAN     : read=${VOL_SAN_READ} ms, write=${VOL_SAN_WRITE} ms"
  echo "Vol IO Size : read=${VOL_IO_READ} B, write=${VOL_IO_WRITE} B"
fi
echo "=============================================="

#######################################
# COMPRESSION
#######################################

echo "[9/9] Compressing logs into ZIP..."
ZIP_FILE="${PREFIX}.zip"
if zip -j -m "$ZIP_FILE" "${PREFIX}"* 1>/dev/null; then
    echo "[✓] Success: $ZIP_FILE"
else
    echo "[!] Zip failed. Logs kept in $OUTDIR"
fi
