#!/usr/bin/env bash
# collect_ebpf_v4.2.sh - In-Kernel Histogram Generation (Fixed Dev_t Math)
set -euo pipefail

DEV="nvme1n1"                              # ATENCAO: Ajuste para dm-3 ou nvme1n1 conforme seu teste
DURATION=300
OUTDIR="/var/log/san_debug"

mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d_%H%M%S)"
PREFIX="${OUTDIR}/${TS}_${DEV}"

# Calcula o Major e Minor do dispositivo
MAJ=$(stat -L -c %t "/dev/$DEV")
MIN=$(stat -L -c %T "/dev/$DEV")

# CONSERTO DA CAUSA RAIZ: Calculo moderno do dev_t no Linux (Major << 20 | Minor)
MAJ_DEC=$((16#$MAJ))
MIN_DEC=$((16#$MIN))
DEV_DEC=$(( (MAJ_DEC << 20) | MIN_DEC ))

echo "=== STARTING KERNEL HISTOGRAM CAPTURE v4.2 ==="
echo "  Target  : /dev/$DEV (Major: $MAJ_DEC, Minor: $MIN_DEC)"
echo "  Kernel ID: $DEV_DEC"
echo "  Duration: ${DURATION}s"

echo "[*] Activating in-kernel bpftrace engine..."
env BPFTRACE_MAP_KEYS=500000 bpftrace -e '
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
# Dá o sinal para o bpftrace imprimir os histogramas e encerrar
kill -SIGINT $PID_BPF 2>/dev/null || true

# IMPORTANTE: Espera 3 segundos para dar tempo do bpftrace escrever no arquivo
sleep 3 
pkill -P $$ 2>/dev/null || true

echo "[*] Packaging data..."
zip -j -m "${PREFIX}_bundle.zip" "${PREFIX}"* 1>/dev/null
echo "[SUCCESS] Histograms saved in ${PREFIX}_bundle.zip"
