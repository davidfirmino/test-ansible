#!/usr/bin/env bash
# collect_san_debug_v3.40.sh - Raw IO Capture for Detailed Analytics
set -euo pipefail

# --- CONFIGURATION ---
DEV="dm-3"
DURATION=300
OUTDIR="/var/log/san_debug"
# --------------------

mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d_%H%M%S)"
PREFIX="${OUTDIR}/${TS}_${DEV}"

MAJ=$(stat -L -c %t "/dev/$DEV")
MIN=$(stat -L -c %T "/dev/$DEV")
DEV_DEC=$((16#$MAJ * 256 + 16#$MIN))

echo "=== STARTING RAW IO CAPTURE v3.40 ==="
echo "  Target: /dev/$DEV (ID: $DEV_DEC) | Time: ${DURATION}s"

# bpftrace engine: Captures every single IO completion
bpftrace -e '
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
}' > "${PREFIX}_raw_io.log" &
PID_BPF=$!

# Background metrics for context
iostat -x -k -t 1 "$DURATION" "/dev/$DEV" > "${PREFIX}_iostat.log" &

for ((i=1; i<=DURATION; i++)); do
    printf "\r[%-20s] %s seconds remaining..." "$(printf '#%.0s' $(seq 1 $((i*20/DURATION))))" "$((DURATION - i))"
    sleep 1
done

kill $PID_BPF 2>/dev/null || true
pkill -P $$ 2>/dev/null || true
echo -e "\n[*] Collection complete. Data saved to ${PREFIX}_raw_io.log"
