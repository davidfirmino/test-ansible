#!/usr/bin/env bash
# io_histogram.sh
set -euo pipefail

DEV="${1:-dm-2}"
DURATION="${2:-300}"
OUTDIR="/var/log/san_debug"
mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d_%H%M%S)"
OUTFILE="${OUTDIR}/${TS}_${DEV}_histograms.log"

if [[ ! -b "/dev/$DEV" ]]; then
    echo "ERROR: /dev/$DEV is not a block device" >&2
    exit 1
fi

MAJ_HEX=$(stat -L -c '%t' "/dev/$DEV")
MIN_HEX=$(stat -L -c '%T' "/dev/$DEV")
MAJ_DEC=$((16#$MAJ_HEX))
MIN_DEC=$((16#$MIN_HEX))
DEV_DEC=$(( (MAJ_DEC << 20) | MIN_DEC ))

echo "=== IO HISTOGRAM CAPTURE ==="
echo "  Device     : /dev/$DEV  (major=${MAJ_DEC}, minor=${MIN_DEC}, kernel_id=${DEV_DEC})"
echo "  Duration   : ${DURATION}s"
echo "  Output     : ${OUTFILE}"
echo ""

# Detecta qual par de tracepoints esta disponivel
if bpftrace -l 'tracepoint:block:block_io_start' 2>/dev/null | grep -q block_io_start; then
    TP_START="block_io_start"
    TP_DONE="block_io_done"
else
    TP_START="block_rq_insert"
    TP_DONE="block_rq_complete"
fi

echo "  Tracepoints: block:${TP_START} / block:${TP_DONE}"
echo ""

bpftrace -e "
config = { max_map_keys = 2000000 }

tracepoint:block:${TP_START} /args->dev == ${DEV_DEC}/ {
    @start[args->dev, args->sector] = nsecs;
    @rwbs[args->dev, args->sector]  = str(args->rwbs);
    @sz[args->dev, args->sector]    = (uint64)args->nr_sector * 512;
}

tracepoint:block:${TP_DONE} /args->dev == ${DEV_DEC}/ {
    \$st = @start[args->dev, args->sector];
    if (\$st == 0) { return; }

    \$lat_us   = (nsecs - \$st) / 1000;
    \$sz_bytes = @sz[args->dev, args->sector];
    \$rw       = @rwbs[args->dev, args->sector];

    @lat_all_us   = hist(\$lat_us);
    @sz_all_bytes = hist(\$sz_bytes);

    if (\$rw == \"R\" || \$rw == \"RA\" || \$rw == \"RS\" || \$rw == \"RAS\") {
        @lat_read_us   = hist(\$lat_us);
        @sz_read_bytes = hist(\$sz_bytes);
    } else if (\$rw == \"W\" || \$rw == \"WS\" || \$rw == \"WB\" || \$rw == \"WBS\") {
        @lat_write_us   = hist(\$lat_us);
        @sz_write_bytes = hist(\$sz_bytes);
    }

    delete(@start[args->dev, args->sector]);
    delete(@rwbs[args->dev, args->sector]);
    delete(@sz[args->dev, args->sector]);
}

interval:s:${DURATION} { exit(); }

END {
    printf(\"\n╔══════════════════════════════════════════════════════════╗\n\");
    printf(\"║         LATENCY HISTOGRAMS (microseconds, log2)          ║\n\");
    printf(\"╚══════════════════════════════════════════════════════════╝\n\");
    printf(\"\n--- ALL I/O ---\n\");     print(@lat_all_us);
    printf(\"\n--- READS ONLY ---\n\");  print(@lat_read_us);
    printf(\"\n--- WRITES ONLY ---\n\"); print(@lat_write_us);

    printf(\"\n╔══════════════════════════════════════════════════════════╗\n\");
    printf(\"║            IO SIZE HISTOGRAMS (bytes, log2)              ║\n\");
    printf(\"╚══════════════════════════════════════════════════════════╝\n\");
    printf(\"\n--- ALL I/O ---\n\");     print(@sz_all_bytes);
    printf(\"\n--- READS ONLY ---\n\");  print(@sz_read_bytes);
    printf(\"\n--- WRITES ONLY ---\n\"); print(@sz_write_bytes);

    clear(@start); clear(@rwbs); clear(@sz);
    clear(@lat_all_us); clear(@lat_read_us); clear(@lat_write_us);
    clear(@sz_all_bytes); clear(@sz_read_bytes); clear(@sz_write_bytes);
}
" 2>&1 | tee "$OUTFILE"

echo ""
echo "[DONE] Results saved to: $OUTFILE"
