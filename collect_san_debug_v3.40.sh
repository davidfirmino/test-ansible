#!/usr/bin/env bash
# collect_san_debug_v3.41.sh - Raw IO Capture for Detailed Analytics
# Changes in v3.41: Increased MAP_KEYS to prevent drops under high IOPS 
# and added END block to prevent dumping raw map data into the log file.
set -euo pipefail

# --- CONFIGURATION ---
DEV="dm-3"                                 # Target device (without /dev/)
DURATION=300                               # Collection time in seconds
OUTDIR="/var/log/san_debug"
# --------------------

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d_%H%M%S)"
PREFIX="${OUTDIR}/${TS}_${DEV}"

# Calculate Decimal ID of the device for bpftrace filtering
MAJ=$(stat -L -c %t "/dev/$DEV")
MIN=$(stat -L -c %T "/dev/$DEV")
DEV_DEC=$((16#$MAJ * 256 + 16#$MIN))

echo "=== STARTING RAW IO CAPTURE v3.41 ==="
echo "  Target  : /dev/$DEV (ID: $DEV_DEC)"
echo "  Duration: ${DURATION}s"
echo "  Kernel  : $(uname -r)"
echo "  Output  : $OUTDIR"

# bpftrace engine: Increased MAP_KEYS to handle high IOPS
# Output format: [Type R/W] [Size in Bytes] [Latency in us]
echo "[*] Activating bpftrace engine..."
env BPFTRACE_MAP_KEYS=2500000 bpftrace -e '
tracepoint:block:block_rq_issue {
    @start[args->dev, args->sector] = nsecs;
}
tracepoint:block:block_rq_complete /args->dev == '$DEV_DEC'/ {
    if (@start[args->dev, args->sector]) {
        $lat = (nsecs - @start[args->dev, args->sector]) / 1000;
        $rw = (strncmp(args->rwbs, "W", 1) == 0 ? "W" : "R");
        printf("%s %d %d\n", $rw, args->nr_sector * 512, $lat);
        delete(@start[args->dev, args->sector]);
    }
}
END {
    clear(@start);
}' > "${PREFIX}_raw_io.log" &
PID_BPF=$!

# Background metrics for context
echo "[*] Starting background metrics (iostat)..."
iostat -x -k -t 1 "$DURATION" "/dev/$DEV" > "${PREFIX}_iostat.log" &

# Wait Loop with Progress Bar
for ((i=1; i<=DURATION; i++)); do
    printf "\r[%-20s] %s seconds remaining..." "$(printf '#%.0s' $(seq 1 $((i*20/DURATION))))" "$((DURATION - i))"
    sleep 1
done

# Cleanup and Packaging
echo -e "\n[*] Stopping collectors..."
kill $PID_BPF 2>/dev/null || true
pkill -P $$ 2>/dev/null || true

echo "[*] Packaging data into ZIP bundle..."
ZIP_FILE="${PREFIX}_bundle.zip"
zip -j -m "$ZIP_FILE" "${PREFIX}"* 1>/dev/null

echo "========================================"
echo "[SUCCESS] Collection complete: $ZIP_FILE"
echo "Extract _raw_io.log from the bundle and run the analyzer."
