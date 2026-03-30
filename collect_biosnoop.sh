#!/usr/bin/env bash
#
# collect_biosnoop_pure_st.sh
# Focado exclusivamente na coleta de biosnoop para análise de latência granular.
# Requer BCC (BPF Compiler Collection) instalado.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Erro: Este script deve ser executado como root."
   exit 1
fi

#######################################
# CONFIGURAÇÃO PADRÃO
#######################################

DEV="dm-8"          # Dispositivo dm (sem o prefixo /dev/)
DURATION=300       # Duração em segundos
OUTDIR="/var/log/san_debug"

#######################################
# PARSING DE ARGUMENTOS
#######################################

usage() {
  cat <<EOF
Uso: $0 [opções]

Opções:
  --hostdm <dm-N>      Nome do device mapper (padrão: dm-8)
  --duration <seg>     Duração total da coleta (padrão: 300)
  --outdir <caminho>   Diretório de saída (padrão: /var/log/san_debug)

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostdm) DEV="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Opção desconhecida: $1"; usage; exit 1 ;;
  esac
done

#######################################
# PREPARAÇÃO E CHECAGEM
#######################################

mkdir -p "$OUTDIR"
TS="$(date +%F_%H%M%S)"
PREFIX="${OUTDIR}/${TS}_${DEV}"

# Localizar binários do BCC
if [ -f /usr/share/bcc/tools/biosnoop ]; then
    BIOSNOOP_BIN="/usr/share/bcc/tools/biosnoop"
elif [ -f /usr/sbin/biosnoop-bpfcc ]; then
    BIOSNOOP_BIN="/usr/sbin/biosnoop-bpfcc"
else
    BIOSNOOP_BIN="biosnoop"
fi

# Validar comandos necessários
REQUIRED_CMDS="zip $BIOSNOOP_BIN awk"
for cmd in $REQUIRED_CMDS; do
    if ! command -v "$cmd" &> /dev/null && [ ! -f "$cmd" ]; then
        echo "Erro: Comando/ferramenta '$cmd' não encontrada. Instale o pacote BCC."
        exit 1
    fi
done

echo "=== Coleta Biosnoop para Pure //ST ==="
echo "  Dispositivo : $DEV"
echo "  Duração     : ${DURATION}s"
echo "  Saída       : $OUTDIR"
echo "======================================"

#######################################
# TRAP PARA LIMPEZA
#######################################
cleanup() {
    tput cnorm 2>/dev/null || true
    echo ""
    echo "[!] Parando coletores..."
    pkill -P $$ 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

#######################################
# INÍCIO DA COLETA
#######################################

echo "[*] Iniciando captura do biosnoop no dispositivo $DEV..."
# Captura o biosnoop em background
$BIOSNOOP_BIN -Q -d "$DEV" > "${PREFIX}_biosnoop_raw_${DEV}.log" 2>/dev/null &
PID_BIOSNOOP=$!

#######################################
# LOOP DE ESPERA
#######################################

tput civis 2>/dev/null || true
for ((i=1; i<=DURATION; i++)); do
    printf "\r[Executando] %-3s segundos restantes..." "$((DURATION - i))"
    sleep 1
done
tput cnorm 2>/dev/null || true
echo ""

#######################################
# PÓS-PROCESSAMENTO
#######################################

echo "[*] Finalizando processo e formatando logs..."
if [[ -n "${PID_BIOSNOOP:-}" ]]; then
    kill "$PID_BIOSNOOP" 2>/dev/null || true
fi

# Processamento para o formato esperado pelo script Python (adiciona timestamp absoluto)
if [ -s "${PREFIX}_biosnoop_raw_${DEV}.log" ]; then
    awk 'BEGIN{
             OFS="\t";
             print "WALL_TIME","TIME(s)","COMM","PID","DISK","T","SECTOR","BYTES","QUE(ms)","LAT(ms)";
         }
         NR>1{
             print strftime("%H:%M:%S"),$0;
         }' \
      "${PREFIX}_biosnoop_raw_${DEV}.log" > "${PREFIX}_biosnoop_tail_${DEV}.log" 2>/dev/null || true
    echo "[✓] Log processado: ${PREFIX}_biosnoop_tail_${DEV}.log"
else
    echo "Aviso: O log do biosnoop está vazio. Verifique se há I/O no disco durante o teste."
fi

#######################################
# COMPRESSÃO
#######################################

echo "[*] Compactando arquivos..."
ZIP_FILE="${PREFIX}_biosnoop.zip"
if zip -j -m "$ZIP_FILE" "${PREFIX}"* 1>/dev/null; then
    echo "[✓] Sucesso: $ZIP_FILE"
else
    echo "[!] Falha ao criar ZIP. Logs mantidos em $OUTDIR"
fi
