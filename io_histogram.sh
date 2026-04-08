#!/usr/bin/env bash
# io_histogram_v6.sh - Auto-Discover Omni-Capture
set -euo pipefail

DEV="${1:-dm-3}"
DURATION="${2:-10}"
OUTDIR="/var/log/san_debug"
mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d_%H%M%S)"
RAWFILE="${OUTDIR}/${TS}_raw.log"
OUTFILE="${OUTDIR}/${TS}_${DEV}_histograms.log"

echo "=== IO HISTOGRAM SMART CAPTURE v6.0 ==="
echo "  Target Device : /dev/$DEV"
echo "  Duration      : ${DURATION}s"

# 1. Descobre todos os discos relacionados (o DM e as pernas fisicas)
if command -v lsblk >/dev/null 2>&1; then
    TARGET_DEVS=$(lsblk -n -r -o KNAME -s "/dev/$DEV" | tr '\n' ' ')
else
    TARGET_DEVS="$DEV"
fi
echo "  Monitoring    : $TARGET_DEVS"

echo "[*] Activating Global BPF Capture (gathering all IOs)..."

# 2. Captura TUDO do servidor sem filtros estritos
env BPFTRACE_MAP_KEYS=5000000 bpftrace -e '
tracepoint:block:block_rq_issue {
    @start[args->dev, args->sector] = nsecs;
    @is_w[args->dev, args->sector] = (strncmp(args->rwbs, "W", 1) == 0 || strncmp(args->rwbs, "F", 1) == 0);
}
tracepoint:block:block_rq_complete {
    $st = @start[args->dev, args->sector];
    if ($st != 0) {
        $lat_us = (nsecs - $st) / 1000;
        if (@is_w[args->dev, args->sector]) {
            @lat_write_us[args->dev] = hist($lat_us);
        } else {
            @lat_read_us[args->dev] = hist($lat_us);
        }
        delete(@start[args->dev, args->sector]);
        delete(@is_w[args->dev, args->sector]);
    }
}
interval:s:'$DURATION' { exit(); }
END { clear(@start); clear(@is_w); }
' > "$RAWFILE" 2>/dev/null

echo "[*] Processing and filtering results for $DEV..."

# 3. Traduz os IDs do Kernel para nomes reais e filtra apenas o que interessa
python3 -c '
import sys, os, re

target_devs = sys.argv[1].split()
raw_file = sys.argv[2]
out_file = sys.argv[3]

def get_dev_name(dev_t):
    # Deslocamento de 20 bits do Kernel Linux Moderno
    maj = dev_t >> 20
    min = dev_t & 0xFFFFF
    sys_path = f"/sys/dev/block/{maj}:{min}"
    if os.path.exists(sys_path):
        return os.path.basename(os.path.realpath(sys_path))
    return f"unknown_{dev_t}"

has_data = False
with open(raw_file, "r") as fin, open(out_file, "w") as fout:
    fout.write(f"=== LATENCY REPORT FOR: {target_devs[0]} ===\n")
    keep = False
    for line in fin:
        m = re.match(r"^@([a-zA-Z_]+)\[(\d+)\]:", line)
        if m:
            map_name = m.group(1)
            dev_t = int(m.group(2))
            dev_name = get_dev_name(dev_t)
            
            # Só mantém se for o dm-3 ou suas pernas físicas (ex: nvme1n1)
            if dev_name in target_devs:
                keep = True
                has_data = True
                op = "WRITES" if "write" in map_name else "READS"
                fout.write(f"\n--- {op} LATENCY (microseconds, log2) | DEVICE: {dev_name} ---\n")
            else:
                keep = False
        elif keep and line.strip():
            fout.write(line)
            
if not has_data:
    with open(out_file, "a") as fout:
        fout.write("\n[!] Nenhum I/O registrado para este dispositivo durante a captura.\n")
        fout.write("Verifique se o FIO esta rodando e enviando carga para as interfaces mapeadas.\n")
' "$TARGET_DEVS" "$RAWFILE" "$OUTFILE"

echo "[SUCCESS] Report generated: $OUTFILE"
echo "--------------------------------------------------------"
cat "$OUTFILE"
