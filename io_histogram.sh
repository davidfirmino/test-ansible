#!/usr/bin/env bash
# io_analyzer_pro.sh - High-Precision Tail Analysis (Verifier Optimized)

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
DEV_DEC=$(( (uint64)((MAJ_DEC << 20) | MIN_DEC) ))

echo "=== IO TAIL ANALYZER v10.3 (Pro) ==="
echo "  Device   : /dev/$DEV (ID: $DEV_DEC)"
echo "  Duration : ${DURATION}s"
echo "------------------------------------------------------------------"

env BPFTRACE_MAP_KEYS=5000000 bpftrace -e '
#include <linux/blk_types.h>
#include <linux/blkdev.h>

BEGIN {
    printf("Tracing started. Wait %ds or hit Ctrl+C...\n", '$DURATION');
    @ts_start = nsecs;
}

kprobe:submit_bio {
    $bio = (struct bio *)arg0;
    if ((uint64)$bio->bi_bdev->bd_dev == (uint64)'$DEV_DEC') {
        @start[arg0] = nsecs;
        @is_write[arg0] = (uint64)($bio->bi_opf & 1);
        @size[arg0] = (uint64)$bio->bi_iter.bi_size;
    }
}

kprobe:bio_endio /@start[arg0]/ {
    $lat_us = (uint64)(nsecs - @start[arg0]) / 1000;
    $lat_ms = $lat_us / 1000;
    $sz = (uint64)@size[arg0];
    
    if (@is_write[arg0]) { 
        @w_total++; @w_bytes += $sz; @w_lat_total += $lat_us;
        @hist_w = hist($lat_us);
        if ($lat_ms <= 1) { @w_tail_1ms++; }
        else {
            @w_tail_gt1++;
            if ($lat_ms > 2)  { @w_tail_gt2++; }
            if ($lat_ms > 5)  { @w_tail_gt5++; }
            if ($lat_ms > 10) { @w_tail_gt10++; }
            if ($lat_ms > 50) { @w_tail_gt50++; }
        }
    } else { 
        @r_total++; @r_bytes += $sz; @r_lat_total += $lat_us;
        @hist_r = hist($lat_us);
        if ($lat_ms <= 1) { @r_tail_1ms++; }
        else {
            @r_tail_gt1++;
            if ($lat_ms > 2)  { @r_tail_gt2++; }
            if ($lat_ms > 5)  { @r_tail_gt5++; }
            if ($lat_ms > 10) { @r_tail_gt10++; }
            if ($lat_ms > 50) { @r_tail_gt50++; }
        }
    }
    delete(@start[arg0]); delete(@is_write[arg0]); delete(@size[arg0]);
}

interval:s:'$DURATION' { exit(); }

END {
    $duration_s = (nsecs - @ts_start) / 1000000000;
    printf("\nTime Window : %ds | Device: /dev/'$DEV'\n", $duration_s);
    
    $rt = (uint64)@r_total;
    $wt = (uint64)@w_total;
    $tt = $rt + $wt;

    if ($tt > 0) {
        printf("Workload    : Reads: %u | Writes: %u | Avg Size: %u B\n", $rt, $wt, (@r_bytes + @w_bytes) / $tt);
    }

    if ($rt > 0) {
        printf("\n[ READS ONLY ]\n");
        $p1 = (@r_tail_1ms * 10000 / $rt);
        printf("    <= 1 ms  : %-10u (%u.%02u%%)\n", @r_tail_1ms, $p1 / 100, $p1 % 100);
        $p2 = (@r_tail_gt1 * 10000 / $rt);
        printf("    >  1 ms  : %-10u (%u.%02u%%)\n", @r_tail_gt1, $p2 / 100, $p2 % 100);
        $p3 = (@r_tail_gt5 * 10000 / $rt);
        printf("    >  5 ms  : %-10u (%u.%02u%%)\n", @r_tail_gt5, $p3 / 100, $p3 % 100);
        $p4 = (@r_tail_gt50 * 10000 / $rt);
        printf("    > 50 ms  : %-10u (%u.%02u%%)\n", @r_tail_gt50, $p4 / 100, $p4 % 100);
        $avg_r = @r_lat_total / $rt;
        printf("  Average Latency: %u.%03u ms\n", $avg_r / 1000, $avg_r % 1000);
    }

    if ($wt > 0) {
        printf("\n[ WRITES ONLY ]\n");
        $pw1 = (@w_tail_1ms * 10000 / $wt);
        printf("    <= 1 ms  : %-10u (%u.%02u%%)\n", @w_tail_1ms, $pw1 / 100, $pw1 % 100);
        $pw2 = (@w_tail_gt1 * 10000 / $wt);
        printf("    >  1 ms  : %-10u (%u.%02u%%)\n", @w_tail_gt1, $pw2 / 100, $pw2 % 100);
        $pw3 = (@w_tail_gt5 * 10000 / $wt);
        printf("    >  5 ms  : %-10u (%u.%02u%%)\n", @w_tail_gt5, $pw3 / 100, $pw3 % 100);
        $pw4 = (@w_tail_gt50 * 10000 / $wt);
        printf("    > 50 ms  : %-10u (%u.%02u%%)\n", @w_tail_gt50, $pw4 / 100, $pw4 % 100);
        $avg_w = @w_lat_total / $wt;
        printf("  Average Latency: %u.%03u ms\n", $avg_w / 1000, $avg_w % 1000);
    }

    printf("\n[ DETAILED HISTOGRAMS ]\n");
    print(@hist_r); print(@hist_w);
    clear(@start); clear(@is_write); clear(@size);
}
'
