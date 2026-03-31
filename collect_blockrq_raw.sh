#!/usr/bin/env bash
#
# collect_blockrq_raw.sh
# biosnoop-like collector using block raw tracepoints.
# Produces filenames compatible with the existing san_debug_analyzer.py.
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Erro: Este script deve ser executado como root."
   exit 1
fi

DEV="dm-8"
DURATION=300
OUTDIR="/var/log/san_debug"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_PY="${COLLECTOR_PY:-${SCRIPT_DIR}/collect_blockrq_raw.py}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

usage() {
  cat <<EOF
Uso: $0 [opções]

Opções:
  --hostdm <dm-N>      Nome do device mapper (padrão: dm-8)
  --duration <seg>     Duração total da coleta (padrão: 300)
  --outdir <caminho>   Diretório de saída (padrão: /var/log/san_debug)
  --collector <path>   Caminho do collect_blockrq_raw.py
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostdm) DEV="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    --collector) COLLECTOR_PY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Opção desconhecida: $1"; usage; exit 1 ;;
  esac
done

mkdir -p "$OUTDIR"
TS="$(date +%F_%H%M%S)"
PREFIX="${OUTDIR}/${TS}_${DEV}"
RAW_LOG="${PREFIX}_biosnoop_raw_${DEV}.log"
TAIL_LOG="${PREFIX}_biosnoop_tail_${DEV}.log"
ERR_LOG="${PREFIX}_collector_stderr_${DEV}.log"
ZIP_FILE="${PREFIX}_biosnoop.zip"

REQUIRED_CMDS="zip awk timeout ${PYTHON_BIN}"
for cmd in $REQUIRED_CMDS; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Erro: comando '$cmd' não encontrado."
    exit 1
  fi
done

if [[ ! -f "$COLLECTOR_PY" ]]; then
  echo "Erro: coletor Python não encontrado em: $COLLECTOR_PY"
  exit 1
fi

echo "=== Coleta BlockRQ Raw para Pure //ST ==="
echo "  Dispositivo : $DEV"
echo "  Duração     : ${DURATION}s"
echo "  Saída       : $OUTDIR"
echo "  Coletor     : $COLLECTOR_PY"
echo "=========================================="

cleanup() {
    tput cnorm 2>/dev/null || true
    echo ""
    echo "[!] Encerrando..."
}
trap cleanup EXIT INT TERM

echo "[*] Iniciando captura block_rq_* para o dispositivo $DEV..."
# timeout envia SIGINT para permitir flush limpo do Python.
timeout --signal=INT --kill-after=5 "${DURATION}" \
  "$PYTHON_BIN" "$COLLECTOR_PY" -d "$DEV" > "$RAW_LOG" 2> "$ERR_LOG" &
COL_PID=$!

tput civis 2>/dev/null || true
for ((i=0; i<DURATION; i++)); do
    if ! kill -0 "$COL_PID" 2>/dev/null; then
        break
    fi
    printf "\r[Executando] %-3s segundos restantes..." "$((DURATION - i))"
    sleep 1 || true
done
wait "$COL_PID" 2>/dev/null || true
tput cnorm 2>/dev/null || true
echo ""

echo "[*] Pós-processando logs..."
if [[ -s "$RAW_LOG" ]]; then
    awk 'BEGIN{OFS="\t"; print "WALL_TIME","TIME(s)","COMM","PID","DISK","T","SECTOR","BYTES","QUE(ms)","LAT(ms)"}
         NR>1{print strftime("%H:%M:%S"),$0;}' "$RAW_LOG" > "$TAIL_LOG" 2>/dev/null || true
    echo "[✓] Log processado: $TAIL_LOG"
else
    echo "Aviso: O log raw está vazio. Veja também: $ERR_LOG"
fi

echo "[*] Compactando arquivos..."
if zip -j -m "$ZIP_FILE" "${PREFIX}"* >/dev/null; then
    echo "[✓] Sucesso: $ZIP_FILE"
else
    echo "[!] Falha ao criar ZIP. Logs mantidos em $OUTDIR"
fi
