#!/usr/bin/env bash
# io_analyzer_pro.sh - High-Precision Tail Analysis (No-Float Version)

DEV="${1:-dm-3}"
DURATION="${2:-60}"

if [[ ! -b "/dev/$DEV" ]]; then
    echo "ERROR: /dev/$DEV is not a block device."
    exit 1
fi

MAJ_HEX=$(stat -L -c '%t' "/dev/$DEV")
MIN_HEX=$(stat -L -c '%T' "/dev/$DEV")
MAJ_DEC=$((16#$MAJ_HEX))
MIN_DEC=$((16#$MIN_HEX))
DEV_DEC=$(( (MAJ_DEC << 20) | MIN_DEC ))

echo "=== IO TAIL ANALYZER v10.1 (Enterprise Compatibility) ==="
echo "  Device   : /dev/$DEV (ID: $DEV_DEC)"
echo "  Duration : ${DURATION}s"
echo "------------------------------------------------------------------"

env BPFTRACE_MAP_KEYS=5000000 bpftrace -e '
#include <linux/blk_types.h>
#include <linux/blkdev.h>

BEGIN {
    printf("Tracing started. Hit Ctrl+C to end early or wait %ds...\n", '$DURATION');
    @ts_start = nsecs;
}

kprobe:submit_bio {
    $bio = (struct bio *)arg0;
    if ($bio->bi_bdev->bd_dev == '$DEV_DEC') {
        @start[arg0] = nsecs;
        @is_write[arg0] = ($bio->bi_opf & 1);
        @size[arg0] = $bio->bi_iter.bi_size;
    }
}

kprobe:bio_endio /@start[arg0]/ {
    $lat_us = (nsecs - @start[arg0]) / 1000;
    $lat_ms = $lat_us / 1000;
    $sz = @size[arg0];
    $w = @is_write[arg0];

    if ($w) { 
        @w_total++; @w_bytes += $sz; @w_lat_total += $lat_us;
        @hist_w = hist($lat_us);
        if ($lat_ms <= 1) { @w_tail_1ms++; }
        if ($lat_ms > 1)  { @w_tail_gt1++; }
        if ($lat_ms > 2)  { @w_tail_gt2++; }
        if ($lat_ms > 5)  { @w_tail_gt5++; }
        if ($lat_ms > 10) { @w_tail_gt10++; }
        if ($lat_ms > 50) { @w_tail_gt50++; }
    } else { 
        @r_total++; @r_bytes += $sz; @r_lat_total += $lat_us;
        @hist_r = hist($lat_us);
        if ($lat_ms <= 1) { @r_tail_1ms++; }
        if ($lat_ms > 1)  { @r_tail_gt1++; }
        if ($lat_ms > 2)  { @r_tail_gt2++; }
        if ($lat_ms > 5)  { @r_tail_gt5++; }
        if ($lat_ms > 10) { @r_tail_gt10++; }
        if ($lat_ms > 50) { @r_tail_gt50++; }
    }

    delete(@start[arg0]); delete(@is_write[arg0]); delete(@size[arg0]);
}

interval:s:'$DURATION' { exit(); }

END {
    $ts_end = nsecs;
    $duration_s = ($ts_end - @ts_start) / 1000000000;
    
    printf("\nTime Window : %ds\n", $duration_s);
    printf("Device      : /dev/'$DEV'\n");
    
    $total_ios = @r_total + @w_total;
    if ($total_ios > 0) {
        printf("Workload    : Reads: %d | Writes: %d | Total: %d | Avg Size: %d B\n", 
            @r_total, @w_total, $total_ios, (@r_bytes + @w_bytes) / $total_ios);
    }

    printf("\n[ READS ONLY ]\n");
    printf("  Total IOs Traced : %d\n", @r_total);
    if (@r_total > 0) {
        printf("    <= 1 ms  : %-10d (%d.%02d%%)\n", @r_tail_1ms, (@r_tail_1ms * 10000 / @r_total) / 100, (@r_tail_1ms * 10000 / @r_total) % 100);
        printf("    >  1 ms  : %-10d (%d.%02d%%)\n", @r_tail_gt1, (@r_tail_gt1 * 10000 / @r_total) / 100, (@r_tail_gt1 * 10000 / @r_total) % 100);
        printf("    >  2 ms  : %-10d (%d.%02d%%)\n", @r_tail_gt2, (@r_tail_gt2 * 10000 / @r_total) / 100, (@r_tail_gt2 * 10000 / @r_total) % 100);
        printf("    >  5 ms  : %-10d (%d.%02d%%)\n", @r_tail_gt5, (@r_tail_gt5 * 10000 / @r_total) / 100, (@r_tail_gt5 * 10000 / @r_total) % 100);
        printf("    > 10 ms  : %-10d (%d.%02d%%)\n", @r_tail_gt10, (@r_tail_gt10 * 10000 / @r_total) / 100, (@r_tail_gt10 * 10000 / @r_total) % 100);
        printf("    > 50 ms  : %-10d (%d.%02d%%)\n", @r_tail_gt50, (@r_tail_gt50 * 10000 / @r_total) / 100, (@r_tail_gt50 * 10000 / @r_total) % 100);
        printf("  Average Latency: %d.%03d ms\n", (@r_lat_total / @r_total) / 1000, (@r_lat_total / @r_total) % 1000);
    }

    printf("\n[ WRITES ONLY ]\n");
    printf("  Total IOs Traced : %d\n", @w_total);
    if (@w_total > 0) {
        printf("    <= 1 ms  : %-10d (%d.%02d%%)\n", @w_tail_1ms, (@w_tail_1ms * 10000 / @w_total) / 100, (@w_tail_1ms * 10000 / @w_total) % 100);
        printf("    >  1 ms  : %-10d (%d.%02d%%)\n", @w_tail_gt1, (@w_tail_gt1 * 10000 / @w_total) / 100, (@w_tail_gt1 * 10000 / @r_total) % 100);
        printf("    >  2 ms  : %-10d (%d.%02d%%)\n", @w_tail_gt2, (@w_tail_gt2 * 10000 / @w_total) / 100, (@w_tail_gt2 * 10000 / @w_total) % 100);
        printf("    >  5 ms  : %-10d (%d.%02d%%)\n", @w_tail_gt5, (@w_tail_gt5 * 10000 / @w_total) / 100, (@w_tail_gt5 * 10000 / @w_total) % 100);
        printf("    > 10 ms  : %-10d (%d.%02d%%)\n", @w_tail_gt10, (@w_tail_gt10 * 10000 / @w_total) / 100, (@w_tail_gt10 * 10000 / @w_total) % 100);
        printf("    > 50 ms  : %-10d (%d.%02d%%)\n", @w_tail_gt50, (@w_tail_gt50 * 10000 / @w_total) / 100, (@w_tail_gt50 * 10000 / @w_total) % 100);
        printf("  Average Latency: %d.%03d ms\n", (@w_lat_total / @w_total) / 1000, (@w_lat_total / @w_total) % 1000);
    }

    printf("\n[ DETAILED HISTOGRAMS ]\n");
    print(@hist_r); print(@hist_w);

    clear(@start); clear(@is_write); clear(@size);
    clear(@hist_r); clear(@hist_w);
}
'
