#!/usr/bin/env bash
# collect_ebpf_v5.sh - Global SAN Capture (Omni-Capture)
set -euo pipefail

DURATION=30
TS="$(date +%Y%m%d_%H%M%S)"
PREFIX="/var/log/san_debug/${TS}_global"

mkdir -p /var/log/san_debug

echo "=== SAN OMNI-CAPTURE v5.0 ==="
echo "  Modo    : Captura Global (Ignorando filtros)"
echo "  Duração : ${DURATION}s"
echo "  Alvo    : TODOS os discos da maquina"

# Captura TUDO e agrupa pelo Major/Minor do kernel automaticamente
env BPFTRACE_MAP_KEYS=3000000 bpftrace -e '
tracepoint:block:block_rq_issue {
    @start[args->dev, args->sector] = nsecs;
}
tracepoint:block:block_rq_complete {
    $st = @start[args->dev, args->sector];
    if ($st != 0) {
        $maj = args->dev >> 20;
        $min = args->dev & 0xFFFFF;
        
        @latency_us[$maj, $min] = hist((nsecs - $st) / 1000);
        delete(@start[args->dev, args->sector]);
    }
}
END {
    clear(@start);
}
' > "${PREFIX}_histograms.log" &
PID_BPF=$!

for ((i=1; i<=DURATION; i++)); do
    printf "\r[%-20s] %s seconds remaining..." "$(printf '#%.0s' $(seq 1 $((i*20/DURATION))))" "$((DURATION - i))"
    sleep 1
done

echo -e "\n[*] Encerrando BPF (isso pode levar 3 segundos)..."
kill -SIGINT $PID_BPF 2>/dev/null || true
sleep 3

echo "[SUCCESS] Arquivo salvo em: ${PREFIX}_histograms.log"
cat "${PREFIX}_histograms.log"
