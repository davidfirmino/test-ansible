#!/usr/bin/env bash
# collect_san_debug_v3.38.sh - bpftrace-based I/O Capture Engine
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

# --- CONFIGURATION ---
DEV="dm-3"                                 # Target device (without /dev/)
IFACES="ens1f1 ens2f1"                     # RoCE Network Interfaces
DURATION=300                               # Collection time in seconds
OUTDIR="/var/log/san_debug"
# --------------------

mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d_%H%M%S)"
PREFIX="${OUTDIR}/${TS}_${DEV}"

# Calculate Decimal ID of the device for bpftrace filtering
MAJ=$(stat -L -c %t "/dev/$DEV")
MIN=$(stat -L -c %T "/dev/$DEV")
DEV_DEC=$((16#$MAJ * 256 + 16#$MIN))

echo "=== STARTING SAN DEBUG COLLECTION v3.38 ==="
echo "  Device  : /dev/$DEV (ID: $DEV_DEC)"
echo "  Duration: ${DURATION}s"
echo "  Kernel  : $(uname -r)"

# 1. Background Standard Collectors
iostat -x -k -t 1 "$DURATION" "/dev/$DEV" > "${PREFIX}_iostat.log" &
mpstat -P ALL 1 "$DURATION" > "${PREFIX}_mpstat.log" &
sar -n DEV 1 "$DURATION" > "${PREFIX}_sar_net.log" &

# 2. The Core: Raw Data Collection via bpftrace
# Log format: [Type R/W] [Size in Bytes] [Latency in us]
echo "[*] Activating bpftrace engine..."
bpftrace -e '
tracepoint:block:block_rq_issue {
    @start[args->dev, args->sector] = nsecs;
}
tracepoint:block:block_rq_complete 
/args->dev == '$DEV_DEC'/ {
    if (@start[args->dev, args->sector]) {
        $lat = (nsecs - @start[args->dev, args->sector]) / 1000;
        $rw = (args->rwbs[0] == 87 ? "W" : "R");
        printf("%s %d %d\n", $rw, args->nr_sector * 512, $lat);
        delete(@start[args->dev, args->sector]);
    }
}' > "${PREFIX}_bpftrace_raw.log" &
PID_BPF=$!

# 3. Wait Loop with Progress Bar
for ((i=1; i<=DURATION; i++)); do
    printf "\r[%-20s] %s seconds remaining..." "$(printf '#%.0s' $(seq 1 $((i*20/DURATION))))" "$((DURATION - i))"
    sleep 1
done
echo -e "\n[*] Collection finished."

# 4. Cleanup and Packaging
kill $PID_BPF 2>/dev/null || true
pkill -P $$ 2>/dev/null || true

echo "[*] Generating ZIP bundle..."
ZIP_FILE="${PREFIX}_bundle.zip"
zip -j -m "$ZIP_FILE" "${PREFIX}"* 1>/dev/null

echo "========================================"
echo "Collection Complete: $ZIP_FILE"
echo "Provide this file for performance analysis."
