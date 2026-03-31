#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

DEV="dm-8"
DURATION=300
OUTDIR="/var/log/san_debug"

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --hostdm <device>     Block device name (default: dm-8)
  --duration <sec>      Collection duration in seconds (default: 300)
  --outdir <path>       Output directory (default: /var/log/san_debug)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostdm) DEV="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

mkdir -p "$OUTDIR"
TS="$(date +%F_%H%M%S)"
PREFIX="${OUTDIR}/${TS}_${DEV}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_PY="${SCRIPT_DIR}/collect_blockio_tp.py"

if [[ ! -f "$COLLECTOR_PY" ]]; then
  echo "Error: collector script not found: $COLLECTOR_PY"
  exit 1
fi

for cmd in zip awk python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: required command not found: $cmd"
    exit 1
  fi
done

echo "=== Block I/O Tracepoint Collector ==="
echo "  Device    : $DEV"
echo "  Duration  : ${DURATION}s"
echo "  Output    : $OUTDIR"
echo "  Collector : $COLLECTOR_PY"
echo "======================================="

cleanup() {
    tput cnorm 2>/dev/null || true
    echo ""
    echo "[!] Stopping collectors..."
    pkill -P $$ 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

RAW_LOG="${PREFIX}_biosnoop_raw_${DEV}.log"
STDERR_LOG="${PREFIX}_collector_stderr_${DEV}.log"
TAIL_LOG="${PREFIX}_biosnoop_tail_${DEV}.log"
ZIP_FILE="${PREFIX}_biosnoop.zip"

echo "[*] Starting block I/O capture for device ${DEV}..."
python3 "$COLLECTOR_PY" --device "$DEV" > "$RAW_LOG" 2> "$STDERR_LOG" &
PID_COLLECTOR=$!

tput civis 2>/dev/null || true
for ((i=1; i<=DURATION; i++)); do
    printf "\r[Running] %-3s seconds remaining..." "$((DURATION - i))"
    sleep 1
done
tput cnorm 2>/dev/null || true
echo ""

echo "[*] Stopping collector and post-processing logs..."
kill "$PID_COLLECTOR" 2>/dev/null || true
wait "$PID_COLLECTOR" 2>/dev/null || true

if [[ -s "$RAW_LOG" ]]; then
    awk 'BEGIN{
             OFS="\t";
             print "WALL_TIME","TIME(s)","COMM","PID","DISK","T","SECTOR","BYTES","QUE(ms)","LAT(ms)";
         }
         NR>1{
             print strftime("%H:%M:%S"),$0;
         }' \
      "$RAW_LOG" > "$TAIL_LOG" 2>/dev/null || true
    echo "[✓] Processed log: $TAIL_LOG"
else
    echo "Warning: raw log is empty. Also check: $STDERR_LOG"
fi

echo "[*] Compressing artifacts..."
if zip -j -m "$ZIP_FILE" "${PREFIX}"* >/dev/null; then
    echo "[✓] Success: $ZIP_FILE"
else
    echo "[!] Failed to create ZIP. Logs were kept in $OUTDIR"
fi
