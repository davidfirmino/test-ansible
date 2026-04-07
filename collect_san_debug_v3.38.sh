#!/usr/bin/env bash
#
# collect_san_debug_v3.39.sh
#
# End-to-end SAN debug collector for a single Linux host and one dm device.
# Optimized for Kernel 5.14 (RHCK) and 6.x (UEK).
#
# Changes in v3.39:
# - Fixed bpftrace "Type mismatch" by using strncmp for args->rwbs string comparison.
# - Captures host I/O raw data via bpftrace for high-precision analysis.
# - Packages iostat, mpstat, and sar for context.
#
# Run as root.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

#######################################
# DEFAULT CONFIGURATION
#######################################

DEV="dm-3"                                 # Target DM device (e.g., dm-3)
IFACES="ens1f1 ens2f1"                     # Network interfaces
DURATION=300                               # Seconds to collect data
INTERVAL=1                                 # Sampling interval for system tools
OUTDIR="/var/log/san_debug"

#######################################
# PREPARATION
#######################################

mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d_%H%M%S)"
PREFIX="${OUTDIR}/${TS}_${DEV}"

# Identify Device Major/Minor for bpftrace filtering
MAJ=$(stat -L -c %t "/dev/$DEV")
MIN=$(stat -L -c %T "/dev/$DEV")
# Convert Hex to Decimal
DEV_DEC=$((16#$MAJ * 256 + 16#$MIN))

# Verify dependencies
REQUIRED_CMDS="jq curl sar mpstat zip iostat ss ethtool bpftrace"
for cmd in $REQUIRED_CMDS; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: Command '$cmd' is missing. Please install it."
        exit 1
    fi
done

echo "=== SAN DEBUG COLLECTION v3.39 ==="
echo "  Device      : /dev/$DEV (Decimal ID: $DEV_DEC)"
echo "  Duration    : ${DURATION}s"
echo "  Kernel      : $(uname -r)"
echo "  Output Dir  : $OUTDIR"
echo "=================================="

START_TS="$(date +%s)"

#######################################
# CLEANUP TRAP
#######################################
cleanup() {
    echo ""
    echo "[!] Stopping collectors and cleaning up..."
    # Kill background jobs in this shell's process group
    pkill -P $$ 2>/dev/null || true
    wait 2>/dev/null || true
    echo "[!] Done."
}
trap cleanup EXIT INT TERM

#######################################
# BACKGROUND COLLECTION
#######################################

echo "[1/4] Starting standard system metrics (iostat, mpstat, sar)..."
iostat -x -k -t "$INTERVAL" "$DURATION" "/dev/$DEV" > "${PREFIX}_iostat.log" &
mpstat -P ALL "$INTERVAL" "$DURATION" > "${PREFIX}_mpstat.log" &
sar -n DEV "$INTERVAL" "$DURATION" > "${PREFIX}_sar_net.log" &

echo "[2/4] Starting bpftrace raw I/O engine..."
# We use strncmp because Kernel 5.14+ treats rwbs as a string pointer
# Output format: [R/W] [Size_Bytes] [Latency_us]
bpftrace -e '
tracepoint:block:block_rq_issue {
    @start[args->dev, args->sector] = nsecs;
}
tracepoint:block:block_rq_complete 
/args->dev == '$DEV_DEC'/ {
    if (@start[args->dev, args->sector]) {
        $lat = (nsecs - @start[args->dev, args->sector]) / 1000;
        $rw = (strncmp(args->rwbs, "W", 1) == 0 ? "W" : "R");
        printf("%s %d %d\n", $rw, args->nr_sector * 512, $lat);
        delete(@start[args->dev, args->sector]);
    }
}' > "${PREFIX}_bpftrace_raw.log" &
PID_BPF=$!

#######################################
# PROGRESS TIMER
#######################################

echo "[3/4] Collection in progress. Please wait..."
for ((i=1; i<=DURATION; i++)); do
    # Simple progress bar logic
    printf "\r[%-20s] %s seconds remaining..." "$(printf '#%.0s' $(seq 1 $((i*20/DURATION))))" "$((DURATION - i))"
    sleep 1
done
echo ""

#######################################
# FINALIZATION
#######################################

echo "[4/4] Finishing and packaging logs..."

# Stop the bpftrace process specifically to flush the buffer
kill "$PID_BPF" 2>/dev/null || true

# Compress everything into a single bundle
ZIP_FILE="${PREFIX}_bundle.zip"
if zip -j -m "$ZIP_FILE" "${PREFIX}"* 1>/dev/null; then
    echo "------------------------------------------------"
    echo "[SUCCESS] Debug bundle created: $ZIP_FILE"
    echo "Run the san_analyzer.py on the extracted _bpftrace_raw.log"
    echo "------------------------------------------------"
else
    echo "[ERROR] Zip failed. Files remain in $OUTDIR"
fi
