#!/usr/bin/env bash
# io_histogram_targeted.sh
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

echo "=== IO HISTOGRAM TARGETED CAPTURE v5.1 ==="
echo "  Target Device : /dev/$DEV"
echo "  Duration      : ${DURATION}s"

# 1. Map physical paths (slaves) if the target is a Multipath device (dm-X)
SLAVES=$(ls -1 /sys/class/block/$DEV/slaves/ 2>/dev/null || echo "")
if [[ -z "$SLAVES" ]]; then
    # If there are no slaves, it is a regular physical drive (e.g., sda, nvme1n1)
    SLAVES="$DEV"
    echo "  Type          : Direct Physical Device"
else
    echo "  Type          : Virtual Multipath (Device Mapper)"
fi

# 2. Build the BPF filter dynamically based on underlying physical devices
BPF_FILTER=""
echo "  Physical Paths:"
for slave in $SLAVES; do
    MAJ_HEX=$(stat -L -c '%t' "/dev/$slave")
    MIN_HEX=$(stat -L -c '%T' "/dev/$slave")
    MAJ_DEC=$((16#$MAJ_HEX))
    MIN_DEC=$((16#$MIN_HEX))
    
    # Modern Linux kernel dev_t calculation (Major << 20 | Minor)
    SLAVE_DEV_DEC=$(( (MAJ_DEC << 20) | MIN_DEC ))
    
    echo "    -> /dev/$slave (Kernel ID: $SLAVE_DEV_DEC)"
    
    if [[ -z "$BPF_FILTER" ]]; then
        BPF_FILTER="(args->dev == $SLAVE_DEV_DEC)"
    else
        BPF_FILTER="$BPF_FILTER || (args->dev == $SLAVE_DEV_DEC)"
    fi
done

echo "  Output File   : ${OUTFILE}"
echo "-----------------------------------------"

# 3. Execute BPFtrace with the targeted filter
env BPFTRACE_MAP_KEYS=3000000 bpftrace -e "

tracepoint:block:block_rq_issue / $BPF_FILTER / {
    @start[args->dev, args->sector] = nsecs;
    @sz[args->dev, args->sector]    = args->nr_sector * 512;
    
    // Determine if it is a Write (W) or Flush (F) by checking the first character safely
    @is_write[args->dev, args->sector] = (strncmp(args->rwbs, \"W\", 1) == 0 || strncmp(args->rwbs, \"F\", 1) == 0);
}

tracepoint:block:block_rq_complete / $BPF_FILTER / {
    \$st = @start[args->dev, args->sector];
    if (\$st == 0) { return; }

    \$lat_us   = (nsecs - \$st) / 1000;
    \$sz_bytes = @sz[args->dev, args->sector];
    \$write    = @is_write[args->dev, args->sector];

    @lat_all_us   = hist(\$lat_us);
    @sz_all_bytes = hist(\$sz_bytes);

    if (\$write) {
        @lat_write_us   = hist(\$lat_us);
        @sz_write_bytes = hist(\$sz_bytes);
    } else {
        @lat_read_us   = hist(\$lat_us);
        @sz_read_bytes = hist(\$sz_bytes);
    }

    delete(@start[args->dev, args->sector]);
    delete(@sz[args->dev, args->sector]);
    delete(@is_write[args->dev, args->sector]);
}

interval:s:${DURATION} { 
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

    // Clear memory cleanly without suppressing the screen output
    clear(@start); clear(@sz); clear(@is_write);
    clear(@lat_all_us); clear(@lat_read_us); clear(@lat_write_us);
    clear(@sz_all_bytes); clear(@sz_read_bytes); clear(@sz_write_bytes);
    
    printf(\"\n--- Collection Finished ---\n\");
    exit(); 
}
" 2>&1 | tee "$OUTFILE"

echo ""
echo "[DONE] Results saved to: $OUTFILE"
