#!/usr/bin/env bash
# raw_latency.sh - BIO Pointer Tracking (Universal)

echo "=== STARTING BIO CAPTURE (Press Ctrl+C to stop) ==="
echo "Let it run with FIO for a few seconds, then press Ctrl+C."
echo "------------------------------------------------------"

env BPFTRACE_MAP_KEYS=5000000 bpftrace -e '
// Universal hook at the entry of any kernel I/O (struct bio *)
kprobe:submit_bio 
{
    @start[arg0] = nsecs;
}

// Universal hook at the completion of the I/O
kprobe:bio_endio 
/@start[arg0]/ 
{
    $lat_us = (nsecs - @start[arg0]) / 1000;
    @global_latency_us = hist($lat_us);
    delete(@start[arg0]);
}

END {
    printf("\n\n=== LATENCY HISTOGRAM (microseconds) ===\n");
    print(@global_latency_us);
    clear(@start);
}
'
