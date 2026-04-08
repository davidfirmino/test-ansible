#!/usr/bin/env bash
# raw_latency.sh - Zero Wrapper, Raw Pointer Tracking

echo "=== STARTING CAPTURE (Press Ctrl+C to stop and view graphs) ==="
echo "Let it run for about 10 seconds with FIO running, then press Ctrl+C."
echo "----------------------------------------------------------------------"

# Removed custom map limits and error redirections.
# If bpftrace fails, we will see the exact error right on the screen.
bpftrace -e '
tracepoint:block:block_rq_issue 
{
    // arg0 is the exact memory address of the I/O request struct. This never changes/fails.
    @start[arg0] = nsecs;
    
    // Save the kernel device ID this I/O belongs to
    @disk[arg0] = args->dev;
    
    // Save whether this is a Write (W) or Flush (F)
    @is_write[arg0] = (strncmp(args->rwbs, "W", 1) == 0 || strncmp(args->rwbs, "F", 1) == 0);
}

tracepoint:block:block_rq_complete /@start[arg0]/ 
{
    $lat_us = (nsecs - @start[arg0]) / 1000;
    
    // Populate the correct histogram (Read or Write)
    if (@is_write[arg0]) {
        @write_latency_us[@disk[arg0]] = hist($lat_us);
    } else {
        @read_latency_us[@disk[arg0]] = hist($lat_us);
    }
    
    // Clear memory to prevent map overflows
    delete(@start[arg0]);
    delete(@disk[arg0]);
    delete(@is_write[arg0]);
}

// Clear temporary tracking maps on exit (Ctrl+C) so they do not pollute the screen
END {
    clear(@start);
    clear(@disk);
    clear(@is_write);
}
'
