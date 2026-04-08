#!/usr/bin/env bash
# collect_ebpf_v4.sh - In-Kernel Histogram Generation
set -euo pipefail

DEV="dm-3"
DURATION=300
OUTDIR="/var/log/san_debug"

mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d_%H%M%S)"
PREFIX="${OUTDIR}/${TS}_${DEV}"

MAJ=$(stat -L -c %t "/dev/$DEV")
MIN=$(stat -L -c %T "/dev/$DEV")
DEV_DEC=$((16#$MAJ * 256 + 16#$MIN))

echo "=== STARTING KERNEL HISTOGRAM CAPTURE v4.0 ==="
echo "  Target  : /dev/$DEV (ID: $DEV_DEC)"
echo "  Duration: ${DURATION}s"

# bpftrace engine: In-kernel histograms (Zero map-full errors)
echo "[*] Activating in-kernel bpftrace engine..."
bpftrace -e '
tracepoint:block:block_rq_issue {
    @start[args->dev, args->sector] = nsecs;
}
tracepoint:block:block_rq_complete /args->dev == '$DEV_DEC'/ {
    if (@start[args->dev, args->sector]) {
        // Calculate latency in microseconds
        $lat = (nsecs - @start[args->dev, args->sector]) / 1000;
        
        // Populate histograms
        @latency_us = hist($lat);
        @io_size_bytes = hist(args->nr_sector * 512);
        
        delete(@start[args->dev, args->sector]);
    }
}
' > "${PREFIX}_histograms.log" &
PID_BPF=$!

iostat -x -k -t 1 "$DURATION" "/dev/$DEV" > "${PREFIX}_iostat.log" &

for ((i=1; i<=DURATION; i++)); do
    printf "\r[%-20s] %s seconds remaining..." "$(printf '#%.0s' $(seq 1 $((i*20/DURATION))))" "$((DURATION - i))"
    sleep 1
done

echo -e "\n[*] Stopping collectors..."
kill -SIGINT $PID_BPF 2>/dev/null || true # SIGINT forces bpftrace to print histograms
pkill -P $$ 2>/dev/null || true
sleep 2 # Give bpftrace time to flush the output

echo "[*] Packaging data..."
zip -j -m "${PREFIX}_bundle.zip" "${PREFIX}"* 1>/dev/null
echo "[SUCCESS] Histograms saved in ${PREFIX}_bundle.zip"
