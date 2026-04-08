#!/usr/bin/env bash
# raw_latency.sh - True Raw Pointer Tracking via kprobes with High IOPS Support

echo "=== STARTING KPROBE CAPTURE (Press Ctrl+C to stop) ==="
echo "Let it run with FIO for a few seconds, then press Ctrl+C."
echo "------------------------------------------------------"

# Forcing 5 million keys to support 130k+ IOPS without filling the map
env BPFTRACE_MAP_KEYS=5000000 bpftrace -e '
config = { max_map_keys = 5000000 }

// Hook exactly when the Linux Block Multi-Queue starts the request
kprobe:blk_mq_start_request 
{
    // arg0 is the exact memory address of the "struct request"
    @start[arg0] = nsecs;
}

// Hook exactly when the Block Multi-Queue completes the request
kprobe:blk_mq_complete_request 
/@start[arg0]/ 
{
    $lat_us = (nsecs - @start[arg0]) / 1000;
    
    // Create a single global histogram of all I/O latency
    @global_latency_us = hist($lat_us);
    
    // Clean up memory immediately to prevent map overflows
    delete(@start[arg0]);
}

// Clear temporary tracking maps on exit so they do not pollute the screen
END {
    clear(@start);
}
'
