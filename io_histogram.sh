#!/usr/bin/env bash
# io_histogram.sh - Block I/O Latency & Size Histogram via bpftrace
# Usage: ./io_histogram.sh <device> [duration_seconds]
# Example: ./io_histogram.sh dm-2 300
set -euo pipefail

DEV="${1:-dm-2}"
DURATION="${2:-300}"
OUTDIR="/var/log/san_debug"
mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d_%H%M%S)"
OUTFILE="${OUTDIR}/${TS}_${DEV}_histograms.log"

# Compute kernel dev_t (modern Linux: major << 20 | minor)
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
echo "  [Ctrl+C or wait ${DURATION}s to print histograms]"
echo ""

bpftrace -e "
config = { max_map_keys = 2000000 }

tracepoint:block:block_rq_issue /args->dev == ${DEV_DEC}/ {
    @start[args->sector] = nsecs;
    @rw[args->sector]    = args->rwbs;
    @sz[args->sector]    = (uint64)args->nr_sector * 512;
}

tracepoint:block:block_rq_complete /args->dev == ${DEV_DEC}/ {
    \$st = @start[args->sector];
    if (\$st == 0) { return; }

    \$lat_us   = (nsecs - \$st) / 1000;
    \$sz_bytes = @sz[args->sector];
    \$rwbs     = @rw[args->sector];

    // All I/O
    @lat_all_us   = hist(\$lat_us);
    @sz_all_bytes = hist(\$sz_bytes);

    // Reads (rwbs starts with R: \"R\", \"RA\", \"RS\", etc.)
    if (strncmp(\$rwbs, \"R\", 1) == 0) {
        @lat_read_us   = hist(\$lat_us);
        @sz_read_bytes = hist(\$sz_bytes);
    }

    // Writes (rwbs starts with W: \"W\", \"WS\", \"WB\", etc.)
    if (strncmp(\$rwbs, \"W\", 1) == 0) {
        @lat_write_us   = hist(\$lat_us);
        @sz_write_bytes = hist(\$sz_bytes);
    }

    delete(@start[args->sector]);
    delete(@rw[args->sector]);
    delete(@sz[args->sector]);
}

interval:s:${DURATION} {
    exit();
}

END {
    printf(\"\n\");
    printf(\"╔══════════════════════════════════════════════════════════╗\n\");
    printf(\"║         LATENCY HISTOGRAMS (microseconds, log2)          ║\n\");
    printf(\"╚══════════════════════════════════════════════════════════╝\n\");

    printf(\"\n--- ALL I/O ---\n\");
    print(@lat_all_us);

    printf(\"\n--- READS ONLY ---\n\");
    print(@lat_read_us);

    printf(\"\n--- WRITES ONLY ---\n\");
    print(@lat_write_us);

    printf(\"\n╔══════════════════════════════════════════════════════════╗\n\");
    printf(\"║            IO SIZE HISTOGRAMS (bytes, log2)              ║\n\");
    printf(\"╚══════════════════════════════════════════════════════════╝\n\");

    printf(\"\n--- ALL I/O ---\n\");
    print(@sz_all_bytes);

    printf(\"\n--- READS ONLY ---\n\");
    print(@sz_read_bytes);

    printf(\"\n--- WRITES ONLY ---\n\");
    print(@sz_write_bytes);

    // Suppress auto-print of raw maps
    clear(@start);
    clear(@rw);
    clear(@sz);
    clear(@lat_all_us);
    clear(@lat_read_us);
    clear(@lat_write_us);
    clear(@sz_all_bytes);
    clear(@sz_read_bytes);
    clear(@sz_write_bytes);
}
" 2>&1 | tee "$OUTFILE"

echo ""
echo "[DONE] Results saved to: $OUTFILE"
