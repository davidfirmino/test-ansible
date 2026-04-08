#!/usr/bin/env bash
# io_histogram.sh - Targeted BIO Latency Capture (Zero Python)

DEV="${1:-dm-3}"
DURATION="${2:-10}"

if [[ ! -b "/dev/$DEV" ]]; then
    echo "ERROR: /dev/$DEV is not a valid block device."
    exit 1
fi

# Calculates the Kernel Decimal ID for the target device
MAJ_HEX=$(stat -L -c '%t' "/dev/$DEV")
MIN_HEX=$(stat -L -c '%T' "/dev/$DEV")
MAJ_DEC=$((16#$MAJ_HEX))
MIN_DEC=$((16#$MIN_HEX))
DEV_DEC=$(( (MAJ_DEC << 20) | MIN_DEC ))

echo "=== SMART BIO CAPTURE v8.0 ==="
echo "  Target Device : /dev/$DEV (Kernel ID: $DEV_DEC)"
echo "  Duration      : ${DURATION}s"
echo "  Action        : Please wait... histograms will print automatically."
echo "------------------------------------------------------------------"

# Run bpftrace injecting the bash variables directly into the C code
env BPFTRACE_MAP_KEYS=5000000 bpftrace -e '
#include <linux/blk_types.h>
#include <linux/blkdev.h>

kprobe:submit_bio 
{
    $bio = (struct bio *)arg0;
    
    // Check if the I/O matches your targeted device (e.g. dm-3)
    if ($bio->bi_bdev->bd_dev == '$DEV_DEC') {
        @start[arg0] = nsecs;
        
        // In the Linux kernel, bit 0 of bi_opf indicates a Write operation
        @is_write[arg0] = ($bio->bi_opf & 1);
    }
}

kprobe:bio_endio 
/@start[arg0]/ 
{
    $lat_us = (nsecs - @start[arg0]) / 1000;
    
    // Sort the latency into Read or Write histograms
    if (@is_write[arg0]) {
        @write_latency_us = hist($lat_us);
    } else {
        @read_latency_us = hist($lat_us);
    }
    
    delete(@start[arg0]);
    delete(@is_write[arg0]);
}

// Automatically stop and print after X seconds
interval:s:'$DURATION' { exit(); }

END {
    printf("\n\n=== LATENCY REPORT FOR /dev/'$DEV' ===\n");
    clear(@start); 
    clear(@is_write);
}
'
