#!/usr/bin/env python3
# san_analyzer.py - Statistical SAN Latency Processor
import sys
import numpy as np

def format_bytes(size):
    if size >= 1024*1024: return f"{size/(1024*1024):.1f} MiB"
    if size >= 1024: return f"{size/1024:.1f} KiB"
    return f"{size:.0f} B"

def analyze_subset(data, label):
    if len(data) == 0:
        print(f"\n  ({label} ONLY) - No data recorded.")
        return
    
    lats = data[:, 2] / 1000.0  # Convert microseconds to milliseconds
    sizes = data[:, 1]
    total = len(lats)
    
    print(f"\n  ({label} ONLY)")
    print(f"    Total IOs Traced : {total}")
    
    # Tail Distribution
    print(f"    Tail Distribution (Accumulated > X, plus <=1ms):")
    le1 = np.sum(lats <= 1)
    print(f"      <= 1 ms        : {le1:8} ({le1/total*100:8.4f}%)")
    for b in [1, 2, 3, 4, 5, 10, 20, 50]:
        count = np.sum(lats > b)
        print(f"      > {b:2} ms        : {count:8} ({count/total*100:8.4f}%)")

    # Latency Percentiles
    print(f"    Latency Percentiles (ms):")
    print(f"      Avg            : {np.mean(lats):.3f}")
    for p in [50, 90, 95, 99, 99.9, 99.99]:
        suffix = " (Micro-stalls)" if p == 99.99 else ""
        print(f"      P{p:<13} : {np.percentile(lats, p):.3f}{suffix}")
    print(f"      Max            : {np.max(lats):.2f}")

    # IO Size per Bucket
    print(f"    IO Size per Latency Bucket (Avg):")
    # Bucket <= 1ms
    mask = lats <= 1
    if np.any(mask):
        m_size = np.mean(sizes[mask])
        print(f"      <=1    : {np.sum(mask):8} IOs, avg {int(m_size):6} B ({format_bytes(m_size)})")
    
    # Interval Buckets
    bounds = [1, 2, 3, 4, 5, 10, 20, 50]
    for i in range(len(bounds)-1):
        low, high = bounds[i], bounds[i+1]
        mask = (lats > low) & (lats <= high)
        if np.any(mask):
            m_size = np.mean(sizes[mask])
            print(f"      {low}-{high:<4} : {np.sum(mask):8} IOs, avg {int(m_size):6} B ({format_bytes(m_size)})")
    
    # Bucket > 50ms
    mask = lats > 50
    if np.any(mask):
        m_size = np.mean(sizes[mask])
        print(f"      >50    : {np.sum(mask):8} IOs, avg {int(m_size):6} B ({format_bytes(m_size)})")

def main(logfile):
    raw_data = []
    print(f"Reading file: {logfile}...")
    try:
        with open(logfile, 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) == 3:
                    # Convert: [R/W -> 1/0, Size, Lat]
                    raw_data.append([1 if parts[0]=='R' else 0, int(parts[1]), int(parts[2])])
    except FileNotFoundError:
        print("Error: File not found.")
        return

    if not raw_data:
        print("File empty or contains no valid data.")
        return

    data = np.array(raw_data)
    reads = data[data[:, 0] == 1]
    writes = data[data[:, 0] == 0]
    
    print("\n===== SAN DEBUG ANALYZER REPORT v3.38 =====")
    print(f"Workload    : Read {len(reads)/len(data)*100:.1f}% / Write {len(writes)/len(data)*100:.1f}%")
    print(f"Avg Size    : {format_bytes(np.mean(data[:,1]))}")
    print("-" * 50)
    
    analyze_subset(data, "ALL OPS")
    analyze_subset(reads, "READS")
    analyze_subset(writes, "WRITES")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 san_analyzer.py <bpftrace_raw.log>")
    else:
        main(sys.argv[1])
