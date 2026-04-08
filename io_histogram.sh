#!/usr/bin/env bash
# io_histogram.sh - BIO Latency Capture with Human Summary

DEV="${1:-dm-3}"
DURATION="${2:-10}"

if [[ ! -b "/dev/$DEV" ]]; then
    echo "ERROR: /dev/$DEV is not a valid block device."
    exit 1
fi

MAJ_HEX=$(stat -L -c '%t' "/dev/$DEV")
MIN_HEX=$(stat -L -c '%T' "/dev/$DEV")
MAJ_DEC=$((16#$MAJ_HEX))
MIN_DEC=$((16#$MIN_HEX))
DEV_DEC=$(( (MAJ_DEC << 20) | MIN_DEC ))

echo "=== SMART BIO CAPTURE v9.0 ==="
echo "  Target Device : /dev/$DEV (Kernel ID: $DEV_DEC)"
echo "  Duration      : ${DURATION}s"
echo "  Action        : Capturing I/O... please wait."
echo "------------------------------------------------------------------"

env BPFTRACE_MAP_KEYS=5000000 bpftrace -e '
#include <linux/blk_types.h>
#include <linux/blkdev.h>

BEGIN {
    // Inicializa contadores em zero para a tabela final
    @r_total = 0; @r_1ms = 0; @r_10ms = 0; @r_100ms = 0;
    @w_total = 0; @w_1ms = 0; @w_10ms = 0; @w_100ms = 0;
}

kprobe:submit_bio 
{
    $bio = (struct bio *)arg0;
    if ($bio->bi_bdev->bd_dev == '$DEV_DEC') {
        @start[arg0] = nsecs;
        @is_write[arg0] = ($bio->bi_opf & 1);
    }
}

kprobe:bio_endio 
/@start[arg0]/ 
{
    $lat_us = (nsecs - @start[arg0]) / 1000;
    
    if (@is_write[arg0]) {
        @write_latency_us = hist($lat_us);
        @w_total++;
        if ($lat_us >= 1000)   { @w_1ms++; }
        if ($lat_us >= 10000)  { @w_10ms++; }
        if ($lat_us >= 100000) { @w_100ms++; }
    } else {
        @read_latency_us = hist($lat_us);
        @r_total++;
        if ($lat_us >= 1000)   { @r_1ms++; }
        if ($lat_us >= 10000)  { @r_10ms++; }
        if ($lat_us >= 100000) { @r_100ms++; }
    }
    
    delete(@start[arg0]);
    delete(@is_write[arg0]);
}

interval:s:'$DURATION' { exit(); }

END {
    printf("\n\n=== LATENCY REPORT FOR /dev/'$DEV' ===\n");
    
    printf("\n[ HUMAN READABLE SUMMARY ]\n");
    printf("---------------------------------------------------------------------\n");
    printf(" OPERATION | TOTAL I/Os  | > 1ms (Stalls) | > 10ms (Slow) | > 100ms \n");
    printf("---------------------------------------------------------------------\n");
    printf(" READS     | %-11d | %-14d | %-13d | %-6d\n", @r_total, @r_1ms, @r_10ms, @r_100ms);
    printf(" WRITES    | %-11d | %-14d | %-13d | %-6d\n", @w_total, @w_1ms, @w_10ms, @w_100ms);
    printf("---------------------------------------------------------------------\n");

    printf("\n[ RAW HISTOGRAMS (Microseconds) ]\n");
    
    // Imprime os gráficos detalhados
    print(@read_latency_us);
    print(@write_latency_us);

    // Limpeza de memoria
    clear(@start); clear(@is_write);
    clear(@read_latency_us); clear(@write_latency_us);
    clear(@r_total); clear(@r_1ms); clear(@r_10ms); clear(@r_100ms);
    clear(@w_total); clear(@w_1ms); clear(@w_10ms); clear(@w_100ms);
}
'
