#!/usr/bin/env python3
"""
collect_blockio_tp.py

Block I/O collector that emits a biosnoop-compatible raw log using standard
block tracepoints and performs request correlation in user space.

Output format:
  TIME(s) COMM PID DISK T SECTOR BYTES QUE(ms) LAT(ms)

Notes:
- Keeps file names stable on purpose.
- Uses block:block_rq_issue and block:block_rq_complete.
- Filters by target device in user space to avoid dev_t encoding surprises in-kernel.
- Correlates issue -> complete in user space using (sector, rwflag) with a len-aware
  best-effort match.
- QUE(ms) is currently emitted as 0.000.
"""

from __future__ import print_function

import argparse
import ctypes as ct
import os
import signal
from collections import defaultdict, deque
from bcc import BPF

BPF_TEXT = r'''
#include <uapi/linux/ptrace.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct data_t {
    u32 event_type;   /* 0=issue, 1=complete */
    u32 pid;
    u32 dev;
    u32 rwflag;
    u64 ts;
    u64 sector;
    u64 len;
    char name[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

#define RWBS_LEN 8
static __always_inline int get_rwflag_tp(const char *rwbs)
{
    int i;
#pragma unroll
    for (i = 0; i < RWBS_LEN; i++) {
        if (rwbs[i] == 'W')
            return 1;
        if (rwbs[i] == '\0')
            return 0;
    }
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_issue)
{
    struct data_t data = {};
    data.event_type = 0;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.dev = args->dev;
    data.rwflag = get_rwflag_tp(args->rwbs);
    data.ts = bpf_ktime_get_ns();
    data.sector = args->sector;
    data.len = args->bytes;
    bpf_get_current_comm(&data.name, sizeof(data.name));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete)
{
    struct data_t data = {};
    data.event_type = 1;
    data.pid = 0;
    data.dev = args->dev;
    data.rwflag = get_rwflag_tp(args->rwbs);
    data.ts = bpf_ktime_get_ns();
    data.sector = args->sector;
    data.len = ((u64)args->nr_sector) << 9;
    __builtin_memset(&data.name, 0, sizeof(data.name));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
'''


class Data(ct.Structure):
    _fields_ = [
        ("event_type", ct.c_uint),
        ("pid", ct.c_uint),
        ("dev", ct.c_uint),
        ("rwflag", ct.c_uint),
        ("ts", ct.c_ulonglong),
        ("sector", ct.c_ulonglong),
        ("len", ct.c_ulonglong),
        ("name", ct.c_char * 16),
    ]


def tracepoint_exists(category: str, event: str) -> bool:
    path = "/sys/kernel/debug/tracing/available_events"
    needle = f"{category}:{event}"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip() == needle:
                    return True
    except Exception:
        pass
    return False


def get_device_major_minor(device: str):
    path = os.path.join("/dev", device)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No such device: {path}")
    st = os.stat(path)
    return os.major(st.st_rdev), os.minor(st.st_rdev)


def split_tp_dev(dev: int):
    # trace/events/block.h prints this field using MAJOR(__entry->dev), MINOR(__entry->dev)
    # For the tracepoint payload, the common split used by BCC tools is major=dev>>20,
    # minor=dev&((1<<20)-1).
    return (dev >> 20), (dev & ((1 << 20) - 1))


class Collector:
    def __init__(self, device: str):
        self.device = device
        self.target_major, self.target_minor = get_device_major_minor(device)
        self.first_ts_ns = None
        self.exiting = False
        self.total_seen = 0
        self.total_matched = 0

        if not tracepoint_exists("block", "block_rq_issue"):
            raise RuntimeError("tracepoint block:block_rq_issue not found")
        if not tracepoint_exists("block", "block_rq_complete"):
            raise RuntimeError("tracepoint block:block_rq_complete not found")

        self.pending = defaultdict(deque)  # key: (sector, rwflag) -> deque[(ts_ns, len, pid, comm)]

        self.b = BPF(text=BPF_TEXT)
        self.b["events"].open_perf_buffer(self._handle_event, page_cnt=256)

    def _dev_matches(self, dev: int) -> bool:
        major, minor = split_tp_dev(dev)
        return major == self.target_major and minor == self.target_minor

    def _handle_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        self.total_seen += 1

        if not self._dev_matches(event.dev):
            return

        self.total_matched += 1
        if self.first_ts_ns is None:
            self.first_ts_ns = int(event.ts)

        key = (int(event.sector), int(event.rwflag))

        if event.event_type == 0:  # issue
            name = event.name.decode("utf-8", "replace").rstrip("\x00")
            self.pending[key].append((int(event.ts), int(event.len), int(event.pid), name))
            return

        # complete
        q = self.pending.get(key)
        if not q:
            return

        chosen_idx = None
        for idx, item in enumerate(q):
            if item[1] == int(event.len):
                chosen_idx = idx
                break
        if chosen_idx is None:
            chosen_idx = 0

        if chosen_idx == 0:
            issue_ts, issue_len, issue_pid, issue_name = q.popleft()
        else:
            issue_ts, issue_len, issue_pid, issue_name = q[chosen_idx]
            del q[chosen_idx]

        if not q:
            self.pending.pop(key, None)

        rel_s = (int(event.ts) - self.first_ts_ns) / 1_000_000_000.0
        lat_ms = (int(event.ts) - issue_ts) / 1_000_000.0
        que_ms = 0.0
        op = "W" if event.rwflag else "R"

        print(
            f"{rel_s:11.6f} {issue_name:<14.14} {issue_pid:<7d} {self.device:<9} {op} "
            f"{int(event.sector):<10d} {issue_len:<7d} {que_ms:7.3f} {lat_ms:7.3f}",
            flush=True,
        )

    def run(self) -> None:
        print("TIME(s)     COMM           PID     DISK      T SECTOR     BYTES   QUE(ms) LAT(ms)")
        while not self.exiting:
            try:
                self.b.perf_buffer_poll(1000)
            except KeyboardInterrupt:
                break


collector_ref = None


def _signal_handler(signum, frame):
    global collector_ref
    if collector_ref is not None:
        collector_ref.exiting = True


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect biosnoop-compatible raw data using block tracepoints")
    parser.add_argument("--device", required=True, help="Block device name, e.g. dm-3 or nvme1n1")
    args = parser.parse_args()

    global collector_ref
    collector_ref = Collector(args.device)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    collector_ref.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
