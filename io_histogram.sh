#!/usr/bin/env bash
# io_analyzer_pro.sh - BIOSNOOP Clone (Percentiles & Tail Math)

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

echo "=== IO TAIL ANALYZER v12.0 (Percentile Edition) ==="
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

    // O uso de count(), sum() e max() previne o erro de 110% (Lost Updates)
    if (@is_write[arg0]) { 
        @w_cnt = count(); @w_bytes = sum($sz); @w_lat = sum($lat_us); @w_max = max($lat_us);
        @hist_w = hist($lat_us);
        if ($lat_ms <= 1) { @w_t_1 = count(); }
        if ($lat_ms > 1)  { @w_t_gt1 = count(); }
        if ($lat_ms > 2)  { @w_t_gt2 = count(); }
        if ($lat_ms > 5)  { @w_t_gt5 = count(); }
        if ($lat_ms > 10) { @w_t_gt10 = count(); }
        if ($lat_ms > 50) { @w_t_gt50 = count(); }
    } else { 
        @r_cnt = count(); @r_bytes = sum($sz); @r_lat = sum($lat_us); @r_max = max($lat_us);
        @hist_r = hist($lat_us);
        if ($lat_ms <= 1) { @r_t_1 = count(); }
        if ($lat_ms > 1)  { @r_t_gt1 = count(); }
        if ($lat_ms > 2)  { @r_t_gt2 = count(); }
        if ($lat_ms > 5)  { @r_t_gt5 = count(); }
        if ($lat_ms > 10) { @r_t_gt10 = count(); }
        if ($lat_ms > 50) { @r_t_gt50 = count(); }
    }
    delete(@start[arg0]); delete(@is_write[arg0]); delete(@size[arg0]);
}

interval:s:'$DURATION' { exit(); }
END { clear(@start); clear(@is_write); clear(@size); }
' 2>/dev/null | awk -v dev="$DEV" -v dur="$DURATION" '
BEGIN {
    print "  Action   : Capturing I/O... please wait."
    rt=0; wt=0; rb=0; wb=0; rlat=0; wlat=0; rmax=0; wmax=0;
    r1=0; rgt1=0; rgt2=0; rgt5=0; rgt10=0; rgt50=0;
    w1=0; wgt1=0; wgt2=0; wgt5=0; wgt10=0; wgt50=0;
}

# Converte os baldes do histograma (ex: 1K = 1024)
function parse_val(v) {
    if (v ~ /K$/) return substr(v, 1, length(v)-1) * 1024;
    if (v ~ /M$/) return substr(v, 1, length(v)-1) * 1048576;
    return v + 0;
}

# Algoritmo de Percentil por Interpolacao Linear
function get_pct(target_pct, total_count, bins, low_arr, up_arr, cnt_arr,    target, running, i, c, frac, val) {
    if (total_count == 0) return 0.0;
    target = total_count * target_pct;
    running = 0;
    for (i=0; i<bins; i++) {
        c = cnt_arr[i];
        if (running + c >= target) {
            if (c == 0) return low_arr[i] / 1000.0;
            frac = (target - running) / c;
            val = low_arr[i] + frac * (up_arr[i] - low_arr[i]);
            return val / 1000.0;
        }
        running += c;
    }
    if (bins > 0) return up_arr[bins-1] / 1000.0;
    return 0.0;
}

/^@r_cnt: ([0-9]+)/ { rt = $2; next }
/^@w_cnt: ([0-9]+)/ { wt = $2; next }
/^@r_bytes: ([0-9]+)/ { rb = $2; next }
/^@w_bytes: ([0-9]+)/ { wb = $2; next }
/^@r_lat: ([0-9]+)/ { rlat = $2; next }
/^@w_lat: ([0-9]+)/ { wlat = $2; next }
/^@r_max: ([0-9]+)/ { rmax = $2; next }
/^@w_max: ([0-9]+)/ { wmax = $2; next }

/^@r_t_1: ([0-9]+)/ { r1 = $2; next }
/^@r_t_gt1: ([0-9]+)/ { rgt1 = $2; next }
/^@r_t_gt2: ([0-9]+)/ { rgt2 = $2; next }
/^@r_t_gt5: ([0-9]+)/ { rgt5 = $2; next }
/^@r_t_gt10: ([0-9]+)/ { rgt10 = $2; next }
/^@r_t_gt50: ([0-9]+)/ { rgt50 = $2; next }

/^@w_t_1: ([0-9]+)/ { w1 = $2; next }
/^@w_t_gt1: ([0-9]+)/ { wgt1 = $2; next }
/^@w_t_gt2: ([0-9]+)/ { wgt2 = $2; next }
/^@w_t_gt5: ([0-9]+)/ { wgt5 = $2; next }
/^@w_t_gt10: ([0-9]+)/ { wgt10 = $2; next }
/^@w_t_gt50: ([0-9]+)/ { wgt50 = $2; next }

/^@hist_r:/ { mode = "R"; hist_lines[hist_count++] = $0; next }
/^@hist_w:/ { mode = "W"; hist_lines[hist_count++] = $0; next }

/^\[/ {
    low_str = substr($1, 2, length($1)-2);
    up_str = substr($2, 1, length($2)-1);
    cnt = $3 + 0;
    low = parse_val(low_str);
    up = parse_val(up_str);
    
    if (mode == "R") {
        r_low[r_bins] = low; r_up[r_bins] = up; r_cnt[r_bins] = cnt; r_bins++;
    } else if (mode == "W") {
        w_low[w_bins] = low; w_up[w_bins] = up; w_cnt[w_bins] = cnt; w_bins++;
    }
    hist_lines[hist_count++] = $0;
    next
}

/^@/ { next }
{ if (mode != "") hist_lines[hist_count++] = $0 }

END {
    tot = rt + wt;
    print "\n=================================================================="
    printf "Time Window : %ds\n", dur
    printf "Device      : /dev/%s\n", dev
    if (tot > 0) {
        # Transformado para KiB conforme pedido
        avg_sz_kib = (rb + wb) / tot / 1024.0;
        printf "Workload    : Read %.1f%% / Write %.1f%% | Avg Size: %.1f KiB\n", (rt*100/tot), (wt*100/tot), avg_sz_kib
    }
    print "------------------------------------------------------------------\n"

    if (rt > 0) {
        print "[ READS ONLY ]"
        printf "  Total IOs Traced : %d\n", rt
        print  "  Tail Distribution (Accumulated):"
        printf "    <= 1 ms  : %-10d (%7.4f%%)\n", r1, (r1*100/rt)
        printf "    >  1 ms  : %-10d (%7.4f%%)\n", rgt1, (rgt1*100/rt)
        printf "    >  2 ms  : %-10d (%7.4f%%)\n", rgt2, (rgt2*100/rt)
        printf "    >  5 ms  : %-10d (%7.4f%%)\n", rgt5, (rgt5*100/rt)
        printf "    > 10 ms  : %-10d (%7.4f%%)\n", rgt10, (rgt10*100/rt)
        printf "    > 50 ms  : %-10d (%7.4f%%)\n", rgt50, (rgt50*100/rt)
        
        print  "  Latency Percentiles (ms):"
        printf "    Avg      : %7.3f\n", (rlat / rt / 1000.0)
        printf "    P50      : %7.3f\n", get_pct(0.50, rt, r_bins, r_low, r_up, r_cnt)
        printf "    P90      : %7.3f\n", get_pct(0.90, rt, r_bins, r_low, r_up, r_cnt)
        printf "    P95      : %7.3f\n", get_pct(0.95, rt, r_bins, r_low, r_up, r_cnt)
        printf "    P99      : %7.3f\n", get_pct(0.99, rt, r_bins, r_low, r_up, r_cnt)
        printf "    P99.9    : %7.3f\n", get_pct(0.999, rt, r_bins, r_low, r_up, r_cnt)
        printf "    P99.99   : %7.3f (Micro-stalls)\n", get_pct(0.9999, rt, r_bins, r_low, r_up, r_cnt)
        printf "    Max      : %7.3f\n", (rmax / 1000.0)
        print ""
    }

    if (wt > 0) {
        print "[ WRITES ONLY ]"
        printf "  Total IOs Traced : %d\n", wt
        print  "  Tail Distribution (Accumulated):"
        printf "    <= 1 ms  : %-10d (%7.4f%%)\n", w1, (w1*100/wt)
        printf "    >  1 ms  : %-10d (%7.4f%%)\n", wgt1, (wgt1*100/wt)
        printf "    >  2 ms  : %-10d (%7.4f%%)\n", wgt2, (wgt2*100/wt)
        printf "    >  5 ms  : %-10d (%7.4f%%)\n", wgt5, (wgt5*100/wt)
        printf "    > 10 ms  : %-10d (%7.4f%%)\n", wgt10, (wgt10*100/wt)
        printf "    > 50 ms  : %-10d (%7.4f%%)\n", wgt50, (wgt50*100/wt)
        
        print  "  Latency Percentiles (ms):"
        printf "    Avg      : %7.3f\n", (wlat / wt / 1000.0)
        printf "    P50      : %7.3f\n", get_pct(0.50, wt, w_bins, w_low, w_up, w_cnt)
        printf "    P90      : %7.3f\n", get_pct(0.90, wt, w_bins, w_low, w_up, w_cnt)
        printf "    P95      : %7.3f\n", get_pct(0.95, wt, w_bins, w_low, w_up, w_cnt)
        printf "    P99      : %7.3f\n", get_pct(0.99, wt, w_bins, w_low, w_up, w_cnt)
        printf "    P99.9    : %7.3f\n", get_pct(0.999, wt, w_bins, w_low, w_up, w_cnt)
        printf "    P99.99   : %7.3f (Micro-stalls)\n", get_pct(0.9999, wt, w_bins, w_low, w_up, w_cnt)
        printf "    Max      : %7.3f\n", (wmax / 1000.0)
        print ""
    }

    print "[ DETAILED HISTOGRAMS ]"
    for (i=0; i<hist_count; i++) {
        if (hist_lines[i] !~ /^$/) {
            print hist_lines[i]
        }
    }
}'
