#!/usr/bin/env bash
# raw_latency_kprobe.sh - True Raw Pointer Tracking via kprobes

echo "=== STARTING KPROBE CAPTURE (Press Ctrl+C to stop) ==="
echo "Let it run with FIO for a few seconds, then press Ctrl+C."
echo "------------------------------------------------------"

bpftrace -e '
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
    
    // Clean up to prevent memory leaks
    delete(@start[arg0]);
}

// Clear temporary tracking maps on exit
END {
    clear(@start);
}
'
