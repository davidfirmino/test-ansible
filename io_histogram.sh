#!/usr/bin/env bash
# io_analyzer_pro.sh - BIOSNOOP Clone v13.0 (Blocksize & Perfect Math)

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

echo "=== IO TAIL ANALYZER v13.0 (Forensic Edition) ==="
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
        @w_cnt = count(); @w_bytes = sum($sz); @w_lat = sum($lat_us); @w_max = max($lat_us);
        @hist_w = hist($lat_us);
        if ($lat_ms <= 1) { @w_t_1 = count(); @w_b_1 = sum($sz); }
        if ($lat_ms > 1)  { @w_t_gt1 = count(); @w_b_gt1 = sum($sz); }
        if ($lat_ms > 2)  { @w_t_gt2 = count(); @w_b_gt2 = sum($sz); }
        if ($lat_ms > 5)  { @w_t_gt5 = count(); @w_b_gt5 = sum($sz); }
        if ($lat_ms > 10) { @w_t_gt10 = count(); @w_b_gt10 = sum($sz); }
        if ($lat_ms > 50) { @w_t_gt50 = count(); @w_b_gt50 = sum($sz); }
    } else { 
        @r_cnt = count(); @r_bytes = sum($sz); @r_lat = sum($lat_us); @r_max = max($lat_us);
        @hist_r = hist($lat_us);
        if ($lat_ms <= 1) { @r_t_1 = count(); @r_b_1 = sum($sz); }
        if ($lat_ms > 1)  { @r_t_gt1 = count(); @r_b_gt1 = sum($sz); }
        if ($lat_ms > 2)  { @r_t_gt2 = count(); @r_b_gt2 = sum($sz); }
        if ($lat_ms > 5)  { @r_t_gt5 = count(); @r_b_gt5 = sum($sz); }
        if ($lat_ms > 10) { @r_t_gt10 = count(); @r_b_gt10 = sum($sz); }
        if ($lat_ms > 50) { @r_t_gt50 = count(); @r_b_gt50 = sum($sz); }
    }
    delete(@start[arg0]); delete(@is_write[arg0]); delete(@size[arg0]);
}

interval:s:'$DURATION' { exit(); }
END { 
    clear(@start); clear(@is_write); clear(@size); 
}
' 2>/dev/null | awk -v dev="$DEV" -v dur="$DURATION" '
BEGIN {
    print "  Action   : Capturing I/O... please wait."
    rt=0; wt=0; rb=0; wb=0; rlat=0; wlat=0; rmax=0; wmax=0;
}

# Funcao auxiliar para converter formato log2 (ex: 16K -> 16384)
function parse_val(v) {
    if (v ~ /K$/) return substr(v, 1, length(v)-1) * 1024;
    if (v ~ /M$/) return substr(v, 1, length(v)-1) * 1048576;
    return v + 0;
}

# Interpolacao linear perfeita e cega a anomalias externas
function get_pct(target_pct, bins, low_arr, up_arr, cnt_arr,    hist_total, target, running, i, c, frac, val) {
    hist_total = 0;
    for (i=0; i<bins; i++) hist_total += cnt_arr[i];
    if (hist_total == 0) return 0.0;
    
    target = hist_total * target_pct;
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

function print_tail(label, cnt, total_cnt, bytes) {
    pct = (total_cnt > 0) ? (cnt * 100.0 / total_cnt) : 0;
    sz = (cnt > 0) ? (bytes / cnt / 1024.0) : 0;
    printf "    %-9s: %-10d (%7.4f%%) | Avg Size: %8.1f KiB\n", label, cnt, pct, sz;
}

/^@r_cnt:/ { rt = $2; next }
/^@w_cnt:/ { wt = $2; next }
/^@r_bytes:/ { rb = $2; next }
/^@w_bytes:/ { wb = $2; next }
/^@r_lat:/ { rlat = $2; next }
/^@w_lat:/ { wlat = $2; next }
/^@r_max:/ { rmax = $2; next }
/^@w_max:/ { wmax = $2; next }

/^@r_t_1:/ { r1 = $2; next }
/^@r_t_gt1:/ { rgt1 = $2; next }
/^@r_t_gt2:/ { rgt2 = $2; next }
/^@r_t_gt5:/ { rgt5 = $2; next }
/^@r_t_gt10:/ { rgt10 = $2; next }
/^@r_t_gt50:/ { rgt50 = $2; next }
/^@r_b_1:/ { rb1 = $2; next }
/^@r_b_gt1:/ { rbgt1 = $2; next }
/^@r_b_gt2:/ { rbgt2 = $2; next }
/^@r_b_gt5:/ { rbgt5 = $2; next }
/^@r_b_gt10:/ { rbgt10 = $2; next }
/^@r_b_gt50:/ { rbgt50 = $2; next }

/^@w_t_1:/ { w1 = $2; next }
/^@w_t_gt1:/ { wgt1 = $2; next }
/^@w_t_gt2:/ { wgt2 = $2; next }
/^@w_t_gt5:/ { wgt5 = $2; next }
/^@w_t_gt10:/ { wgt10 = $2; next }
/^@w_t_gt50:/ { wgt50 = $2; next }
/^@w_b_1:/ { wb1 = $2; next }
/^@w_b_gt1:/ { wbgt1 = $2; next }
/^@w_b_gt2:/ { wbgt2 = $2; next }
/^@w_b_gt5:/ { wbgt5 = $2; next }
/^@w_b_gt10:/ { wbgt10 = $2; next }
/^@w_b_gt50:/ { wbgt50 = $2; next }

/^@hist_r:/ { mode = "R"; hist_lines[hist_count++] = $0; next }
/^@hist_w:/ { mode = "W"; hist_lines[hist_count++] = $0; next }

/^\[/ {
    low_str = substr($1, 2, length($1)-2);
    up_str = substr($2, 1, length($2)-1);
    cnt = $3 + 0;
    
    if (mode == "R") {
        r_low[r_bins] = parse_val(low_str); r_up[r_bins] = parse_val(up_str); r_cnt[r_bins] = cnt; r_bins++;
    } else if (mode == "W") {
        w_low[w_bins] = parse_val(low_str); w_up[w_bins] = parse_val(up_str); w_cnt[w_bins] = cnt; w_bins++;
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
        printf "Workload    : Read %.1f%% / Write %.1f%% | Avg Size: %.1f KiB\n", (rt*100/tot), (wt*100/tot), ((rb + wb) / tot / 1024.0)
    }
    print "------------------------------------------------------------------\n"

    if (rt > 0) {
        print "[ READS ONLY ]"
        printf "  Total IOs Traced : %d\n", rt
        print  "  Tail Distribution (Accumulated):"
        print_tail("<= 1 ms", r1, rt, rb1)
        print_tail(">  1 ms", rgt1, rt, rbgt1)
        print_tail(">  2 ms", rgt2, rt, rbgt2)
        print_tail(">  5 ms", rgt5, rt, rbgt5)
        print_tail("> 10 ms", rgt10, rt, rbgt10)
        print_tail("> 50 ms", rgt50, rt, rbgt50)
        
        print  "  Latency Percentiles (ms):"
        printf "    Avg      : %7.3f\n", (rlat / rt / 1000.0)
        printf "    P50      : %7.3f\n", get_pct(0.50, r_bins, r_low, r_up, r_cnt)
        printf "    P90      : %7.3f\n", get_pct(0.90, r_bins, r_low, r_up, r_cnt)
        printf "    P95      : %7.3f\n", get_pct(0.95, r_bins, r_low, r_up, r_cnt)
        printf "    P99      : %7.3f\n", get_pct(0.99, r_bins, r_low, r_up, r_cnt)
        printf "    P99.9    : %7.3f\n", get_pct(0.999, r_bins, r_low, r_up, r_cnt)
        printf "    P99.99   : %7.3f (Micro-stalls)\n", get_pct(0.9999, r_bins, r_low, r_up, r_cnt)
        printf "    Max      : %7.3f\n\n", (rmax / 1000.0)
    }

    if (wt > 0) {
        print "[ WRITES ONLY ]"
        printf "  Total IOs Traced : %d\n", wt
        print  "  Tail Distribution (Accumulated):"
        print_tail("<= 1 ms", w1, wt, wb1)
        print_tail(">  1 ms", wgt1, wt, wbgt1)
        print_tail(">  2 ms", wgt2, wt, wbgt2)
        print_tail(">  5 ms", wgt5, wt, wbgt5)
        print_tail("> 10 ms", wgt10, wt, wbgt10)
        print_tail("> 50 ms", wgt50, wt, wbgt50)
        
        print  "  Latency Percentiles (ms):"
        printf "    Avg      : %7.3f\n", (wlat / wt / 1000.0)
        printf "    P50      : %7.3f\n", get_pct(0.50, w_bins, w_low, w_up, w_cnt)
        printf "    P90      : %7.3f\n", get_pct(0.90, w_bins, w_low, w_up, w_cnt)
        printf "    P95      : %7.3f\n", get_pct(0.95, w_bins, w_low, w_up, w_cnt)
        printf "    P99      : %7.3f\n", get_pct(0.99, w_bins, w_low, w_up, w_cnt)
        printf "    P99.9    : %7.3f\n", get_pct(0.999, w_bins, w_low, w_up, w_cnt)
        printf "    P99.99   : %7.3f (Micro-stalls)\n", get_pct(0.9999, w_bins, w_low, w_up, w_cnt)
        printf "    Max      : %7.3f\n\n", (wmax / 1000.0)
    }

    print "[ DETAILED HISTOGRAMS ]"
    for (i=0; i<hist_count; i++) {
        if (hist_lines[i] !~ /^$/) {
            print hist_lines[i]
        }
    }
}'
