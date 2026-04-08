#!/usr/bin/env bash
# io_histogram_v7.sh - BIO Layer Omni-Capture + Failsafe
set -euo pipefail

DEV="${1:-dm-3}"
DURATION="${2:-10}"
OUTDIR="/var/log/san_debug"
mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d_%H%M%S)"
RAWFILE="${OUTDIR}/${TS}_raw.log"
OUTFILE="${OUTDIR}/${TS}_${DEV}_histograms.log"

echo "=== IO HISTOGRAM SMART CAPTURE v7.0 ==="
echo "  Target Device : /dev/$DEV"
echo "  Duration      : ${DURATION}s"

# Descobre os discos físicos por trás do dm-3
if command -v lsblk >/dev/null 2>&1; then
    TARGET_DEVS=$(lsblk -n -r -o KNAME -s "/dev/$DEV" | tr '\n' ' ')
else
    TARGET_DEVS="$DEV"
fi
echo "  Monitoring    : $TARGET_DEVS"

# Auto-detecta a melhor camada do Kernel para o Multipath
if bpftrace -l 'tracepoint:block:block_io_start' 2>/dev/null | grep -q block_io_start; then
    TP_START="block_io_start"
    TP_DONE="block_io_done"
    echo "  Kernel Layer  : BIO (Block I/O) - Ideal para Device Mapper"
else
    TP_START="block_rq_issue"
    TP_DONE="block_rq_complete"
    echo "  Kernel Layer  : Request (RQ) - Fallback"
fi

echo "[*] Activating Global BPF Capture (gathering all IOs)..."

env BPFTRACE_MAP_KEYS=5000000 bpftrace -e "
tracepoint:block:${TP_START} {
    @start[args->dev, args->sector] = nsecs;
    @is_w[args->dev, args->sector] = (strncmp(args->rwbs, \"W\", 1) == 0 || strncmp(args->rwbs, \"F\", 1) == 0);
}
tracepoint:block:${TP_DONE} {
    \$st = @start[args->dev, args->sector];
    if (\$st != 0) {
        \$lat_us = (nsecs - \$st) / 1000;
        if (@is_w[args->dev, args->sector]) {
            @lat_write_us[args->dev] = hist(\$lat_us);
        } else {
            @lat_read_us[args->dev] = hist(\$lat_us);
        }
        delete(@start[args->dev, args->sector]);
        delete(@is_w[args->dev, args->sector]);
    }
}
interval:s:${DURATION} { exit(); }
END { clear(@start); clear(@is_w); }
" > "$RAWFILE" 2>/dev/null

echo "[*] Processing and filtering results for $DEV..."

python3 -c '
import sys, os, re

target_devs = sys.argv[1].split()
raw_file = sys.argv[2]
out_file = sys.argv[3]

def get_dev_name(dev_t):
    # Formato Linux Moderno (12 bits major, 20 bits minor)
    maj1 = dev_t >> 20
    min1 = dev_t & 0xFFFFF
    p1 = f"/sys/dev/block/{maj1}:{min1}"
    if os.path.exists(p1): return os.path.basename(os.path.realpath(p1))
    
    # Formato Legado / Fallback (8 bits major, 8 bits minor)
    maj2 = dev_t >> 8
    min2 = dev_t & 0xFF
    p2 = f"/sys/dev/block/{maj2}:{min2}"
    if os.path.exists(p2): return os.path.basename(os.path.realpath(p2))
    
    return f"UNKNOWN_ID_{dev_t}"

has_data = False
found_devices = set()

with open(raw_file, "r") as fin, open(out_file, "w") as fout:
    fout.write(f"=== LATENCY REPORT FOR: {target_devs[0]} ===\n")
    keep = False
    for line in fin:
        m = re.match(r"^@([a-zA-Z_]+)\[(\d+)\]:", line)
        if m:
            map_name = m.group(1)
            dev_t = int(m.group(2))
            dev_name = get_dev_name(dev_t)
            found_devices.add(dev_name)
            
            if dev_name in target_devs:
                keep = True
                has_data = True
                op = "WRITES" if "write" in map_name else "READS"
                fout.write(f"\n--- {op} LATENCY (microseconds, log2) | DEVICE: {dev_name} ---\n")
            else:
                keep = False
        elif keep and line.strip():
            fout.write(line)
            
# O FAILSAFE: Se não achar o dm-3, imprime os IDs que ele achou!
if not has_data:
    with open(out_file, "a") as fout:
        fout.write("\n[!] ALERTA: O Kernel nao reportou trafego com o nome exato desses discos.\n")
        fout.write(f"    Discos Procurados: {target_devs}\n")
        fout.write(f"    Discos Encontrados com Trafego: {list(found_devices)}\n")
        fout.write("\n--- RAW KERNEL DUMP (O que o bpftrace realmente viu) ---\n")
    with open(raw_file, "r") as fin, open(out_file, "a") as fout:
        fout.write(fin.read())
' "$TARGET_DEVS" "$RAWFILE" "$OUTFILE"

echo "[SUCCESS] Report generated: $OUTFILE"
echo "--------------------------------------------------------"
cat "$OUTFILE"
