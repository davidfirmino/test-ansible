#!/usr/bin/env bash
# io_analyzer_pro.sh - High-Precision Tail Analysis (BPF + Awk Formatter)

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

echo "=== IO TAIL ANALYZER v11.0 ==="
echo "  Device   : /dev/$DEV (ID: $DEV_DEC)"
echo "  Duration : ${DURATION}s"
echo "------------------------------------------------------------------"

env BPFTRACE_MAP_KEYS=5000000 bpftrace -e '
#include <linux/blk_types.h>
#include <linux/blkdev.h>

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

    if (@is_write[arg0]) { 
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
    // Imprime os dados brutos para o formatador
    printf("___DATA___ READ %lu %lu %lu %lu %lu %lu %lu %lu %lu\n", 
        @r_total, @r_tail_1ms, @r_tail_gt1, @r_tail_gt2, @r_tail_gt5, @r_tail_gt10, @r_tail_gt50, @r_lat_total, @r_bytes);
    printf("___DATA___ WRITE %lu %lu %lu %lu %lu %lu %lu %lu %lu\n", 
        @w_total, @w_tail_1ms, @w_tail_gt1, @w_tail_gt2, @w_tail_gt5, @w_tail_gt10, @w_tail_gt50, @w_lat_total, @w_bytes);
    
    // Limpeza pesada
    clear(@start); clear(@is_write); clear(@size);
    clear(@r_total); clear(@r_tail_1ms); clear(@r_tail_gt1); clear(@r_tail_gt2); clear(@r_tail_gt5); clear(@r_tail_gt10); clear(@r_tail_gt50); clear(@r_lat_total); clear(@r_bytes);
    clear(@w_total); clear(@w_tail_1ms); clear(@w_tail_gt1); clear(@w_tail_gt2); clear(@w_tail_gt5); clear(@w_tail_gt10); clear(@w_tail_gt50); clear(@w_lat_total); clear(@w_bytes);
}
' 2>/dev/null | awk -v dev="$DEV" -v dur="$DURATION" '
BEGIN {
    print "  Action   : Capturing I/O... please wait."
}
/^___DATA___ READ/ {
    rt=$3; r1=$4; rgt1=$5; rgt2=$6; rgt5=$7; rgt10=$8; rgt50=$9; rlat=$10; rb=$11;
    next
}
/^___DATA___ WRITE/ {
    wt=$3; w1=$4; wgt1=$5; wgt2=$6; wgt5=$7; wgt10=$8; wgt50=$9; wlat=$10; wb=$11;
    
    tot = rt + wt
    if (tot > 0) {
        printf "\nWorkload    : Read %.1f%% / Write %.1f%% | Avg Size: %d B\n", (rt*100/tot), (wt*100/tot), ((rb+wb)/tot)
    }

    if (rt > 0) {
        printf "\n[ READS ONLY ]\n"
        printf "  Total IOs Traced : %d\n", rt
        printf "  Tail Distribution (Accumulated):\n"
        printf "    <= 1 ms  : %-10d (%.4f%%)\n", r1, (r1*100/rt)
        printf "    >  1 ms  : %-10d (%.4f%%)\n", rgt1, (rgt1*100/rt)
        printf "    >  2 ms  : %-10d (%.4f%%)\n", rgt2, (rgt2*100/rt)
        printf "    >  5 ms  : %-10d (%.4f%%)\n", rgt5, (rgt5*100/rt)
        printf "    > 10 ms  : %-10d (%.4f%%)\n", rgt10, (rgt10*100/rt)
        printf "    > 50 ms  : %-10d (%.4f%%)\n", rgt50, (rgt50*100/rt)
        printf "  Average Latency: %.3f ms\n", (rlat / rt / 1000)
    }
    
    if (wt > 0) {
        printf "\n[ WRITES ONLY ]\n"
        printf "  Total IOs Traced : %d\n", wt
        printf "  Tail Distribution (Accumulated):\n"
        printf "    <= 1 ms  : %-10d (%.4f%%)\n", w1, (w1*100/wt)
        printf "    >  1 ms  : %-10d (%.4f%%)\n", wgt1, (wgt1*100/wt)
        printf "    >  2 ms  : %-10d (%.4f%%)\n", wgt2, (wgt2*100/wt)
        printf "    >  5 ms  : %-10d (%.4f%%)\n", wgt5, (wgt5*100/wt)
        printf "    > 10 ms  : %-10d (%.4f%%)\n", wgt10, (wgt10*100/wt)
        printf "    > 50 ms  : %-10d (%.4f%%)\n", wgt50, (wgt50*100/wt)
        printf "  Average Latency: %.3f ms\n", (wlat / wt / 1000)
    }
    printf "\n[ DETAILED HISTOGRAMS ]\n"
    next
}
{ print }
'
