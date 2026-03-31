#!/usr/bin/env bash
#
# collect_blockrq_raw_v5.sh
# biosnoop-like collector using block raw tracepoints.
# Produces filenames compatible with the existing analyzer.
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Error: this script must be run as root."
    exit 1
fi

DEV="dm-8"
DURATION=300
OUTDIR="/var/log/san_debug"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_PY="${COLLECTOR_PY:-${SCRIPT_DIR}/collect_blockrq_raw_v5.py}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

usage() {
    cat <<'EOF'
Usage: collect_blockrq_raw_v5.sh [options]

Options:
  --hostdm <disk>       Disk name to trace, for example dm-8 or nvme0n1
  --duration <sec>      Capture duration in seconds (default: 300)
  --outdir <path>       Output directory (default: /var/log/san_debug)
  --collector <path>    Path to collect_blockrq_raw_v5.py
  -h, --help            Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hostdm) DEV="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --outdir) OUTDIR="$2"; shift 2 ;;
        --collector) COLLECTOR_PY="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

mkdir -p "$OUTDIR"
TS="$(date +%F_%H%M%S)"
PREFIX="${OUTDIR}/${TS}_${DEV}"
RAW_LOG="${PREFIX}_biosnoop_raw_${DEV}.log"
TAIL_LOG="${PREFIX}_biosnoop_tail_${DEV}.log"
ERR_LOG="${PREFIX}_collector_stderr_${DEV}.log"
ZIP_FILE="${PREFIX}_biosnoop.zip"

for cmd in zip awk timeout "$PYTHON_BIN"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command not found: $cmd"
        exit 1
    fi
done

if [[ ! -f "$COLLECTOR_PY" ]]; then
    echo "Error: collector script not found: $COLLECTOR_PY"
    exit 1
fi

echo "=== BlockRQ Raw Collector (biosnoop-like) ==="
echo "  Device     : $DEV"
echo "  Duration   : ${DURATION}s"
echo "  Output dir : $OUTDIR"
echo "  Collector  : $COLLECTOR_PY"
echo "============================================="

action_cleanup() {
    tput cnorm 2>/dev/null || true
    echo
    echo "[!] Exiting..."
}
trap action_cleanup EXIT INT TERM

echo "[*] Starting block_rq_issue/block_rq_complete capture for device $DEV ..."
timeout --signal=INT --kill-after=5 "$DURATION" \
    "$PYTHON_BIN" "$COLLECTOR_PY" -d "$DEV" > "$RAW_LOG" 2> "$ERR_LOG" &
COL_PID=$!

tput civis 2>/dev/null || true
for ((i=0; i<DURATION; i++)); do
    if ! kill -0 "$COL_PID" 2>/dev/null; then
        break
    fi
    printf "\r[Running] %-3s seconds remaining..." "$((DURATION - i))"
    sleep 1 || true
done
wait "$COL_PID" 2>/dev/null || true
tput cnorm 2>/dev/null || true
echo

echo "[*] Post-processing logs ..."
if [[ -s "$RAW_LOG" ]]; then
    awk 'BEGIN{OFS="\t"; print "WALL_TIME","TIME(s)","COMM","PID","DISK","T","SECTOR","BYTES","QUE(ms)","LAT(ms)"}
         NR>1{print strftime("%H:%M:%S"),$0;}' "$RAW_LOG" > "$TAIL_LOG" 2>/dev/null || true
    echo "[+] Tail log created: $TAIL_LOG"
else
    echo "[!] Raw log is empty. Check stderr too: $ERR_LOG"
fi

echo "[*] Packing files ..."
if zip -j -m "$ZIP_FILE" "${PREFIX}"* >/dev/null; then
    echo "[+] Success: $ZIP_FILE"
else
    echo "[!] ZIP creation failed. Files were left in $OUTDIR"
fi
