#!/usr/bin/env bash
# collect_ebpf_v4.1.sh - In-Kernel Histogram Generation (Fixed Map Dump)
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

echo "=== STARTING KERNEL HISTOGRAM CAPTURE v4.1 ==="
echo "  Target  : /dev/$DEV (ID: $DEV_DEC)"
echo "  Duration: ${DURATION}s"

# bpftrace engine:
# 1. Filtramos tudo por DEV_DEC logo na entrada.
# 2. Simplificamos a chave do mapa apenas para 'sector' para poupar CPU/RAM.
# 3. Adicionamos o bloco END para limpar os I/Os orfãos e exibir SÓ os histogramas.
echo "[*] Activating in-kernel bpftrace engine..."
env BPFTRACE_MAP_KEYS=3000000 bpftrace -e '
tracepoint:block:block_rq_issue /args->dev == '$DEV_DEC'/ {
    @start[args->sector] = nsecs;
}
tracepoint:block:block_rq_complete /args->dev == '$DEV_DEC'/ {
    $st = @start[args->sector];
    if ($st != 0) {
        @latency_us = hist((nsecs - $st) / 1000);
        @io_size_bytes = hist(args->nr_sector * 512);
        delete(@start[args->sector]);
    }
}
END {
    clear(@start);
}
' > "${PREFIX}_histograms.log" &
PID_BPF=$!

iostat -x -k -t 1 "$DURATION" "/dev/$DEV" > "${PREFIX}_iostat.log" &

for ((i=1; i<=DURATION; i++)); do
    printf "\r[%-20s] %s seconds remaining..." "$(printf '#%.0s' $(seq 1 $((i*20/DURATION))))" "$((DURATION - i))"
    sleep 1
done

echo -e "\n[*] Stopping collectors..."
kill -SIGINT $PID_BPF 2>/dev/null || true
pkill -P $$ 2>/dev/null || true
sleep 3 # Tempo extra para o bpftrace processar o bloco END e limpar a memória

echo "[*] Packaging data..."
zip -j -m "${PREFIX}_bundle.zip" "${PREFIX}"* 1>/dev/null
echo "[SUCCESS] Histograms saved in ${PREFIX}_bundle.zip"
