#!/usr/bin/env python3
"""
collect_blockrq_tp_v2.py

Biosnoop-compatible raw collector based on standard block tracepoints.

This version avoids raw tracepoints and is tuned for newer kernels where:
- TASK_COMM_LEN may not be visible to the BPF C compiler by default
- block:block_rq_complete exposes nr_sector instead of nr_bytes

Output format:
  TIME(s) COMM PID DISK T SECTOR BYTES QUE(ms) LAT(ms)

Notes:
- QUE(ms) is currently emitted as 0.000
- LAT(ms) is measured from block_rq_issue -> block_rq_complete
"""

from __future__ import print_function

import argparse
import ctypes as ct
import os
import signal
from bcc import BPF

BPF_TEXT = r'''
#include <uapi/linux/ptrace.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct key_t {
    u32 dev;
    u64 sector;
    u32 bytes;
};

struct start_t {
    u64 ts;
    u32 pid;
    u32 bytes;
    u64 sector;
    u32 rwflag;
    char name[TASK_COMM_LEN];
};

struct data_t {
    u32 pid;
    u32 dev;
    u64 rwflag;
    u64 delta;
    u64 qdelta;
    u64 sector;
    u64 len;
    u64 ts;
    char name[TASK_COMM_LEN];
};

BPF_HASH(start, struct key_t, struct start_t);
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
    struct key_t key = {
        .dev = args->dev,
        .sector = args->sector,
        .bytes = args->bytes,
    };

    DEVICE_FILTER

    struct start_t st = {};
    st.ts = bpf_ktime_get_ns();
    st.pid = bpf_get_current_pid_tgid() >> 32;
    st.bytes = args->bytes;
    st.sector = args->sector;
    st.rwflag = get_rwflag_tp(args->rwbs);
    bpf_get_current_comm(&st.name, sizeof(st.name));
    start.update(&key, &st);
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete)
{
    struct key_t key = {
        .dev = args->dev,
        .sector = args->sector,
        .bytes = args->nr_sector << 9,
    };

    DEVICE_FILTER

    struct start_t *stp;
    struct data_t data = {};
    u64 now;

    stp = start.lookup(&key);
    if (!stp)
        return 0;

    now = bpf_ktime_get_ns();
    data.pid = stp->pid;
    data.dev = key.dev;
    data.rwflag = stp->rwflag;
    data.delta = now - stp->ts;
    data.qdelta = 0;
    data.sector = stp->sector;
    data.len = stp->bytes;
    data.ts = now / 1000;
    __builtin_memcpy(&data.name, stp->name, sizeof(data.name));

    events.perf_submit(args, &data, sizeof(data));
    start.delete(&key);
    return 0;
}
'''


class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("dev", ct.c_uint),
        ("rwflag", ct.c_ulonglong),
        ("delta", ct.c_ulonglong),
        ("qdelta", ct.c_ulonglong),
        ("sector", ct.c_ulonglong),
        ("len", ct.c_ulonglong),
        ("ts", ct.c_ulonglong),
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


def get_disk_dev_t(device: str) -> int:
    path = os.path.join("/dev", device)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No such device: {path}")
    st = os.stat(path)
    return (os.major(st.st_rdev) << 20) | os.minor(st.st_rdev)


class Collector:
    def __init__(self, device: str):
        self.device = device
        self.dev_t = get_disk_dev_t(device)
        self.first_ts_us = None
        self.exiting = False

        if not tracepoint_exists("block", "block_rq_issue"):
            raise RuntimeError("tracepoint block:block_rq_issue not found")
        if not tracepoint_exists("block", "block_rq_complete"):
            raise RuntimeError("tracepoint block:block_rq_complete not found")

        bpf_text = BPF_TEXT.replace(
            "DEVICE_FILTER",
            f"if (key.dev != {self.dev_t}) {{ return 0; }}",
        )

        self.b = BPF(text=bpf_text)
        self.b["events"].open_perf_buffer(self._handle_event, page_cnt=256)

    def _handle_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(Data)).contents
        name = event.name.decode("utf-8", "replace").rstrip("\x00")
        op = "W" if event.rwflag else "R"
        lat_ms = float(event.delta) / 1_000_000.0
        que_ms = float(event.qdelta) / 1_000_000.0
        ts_us = int(event.ts)
        if self.first_ts_us is None:
            self.first_ts_us = ts_us
        rel_s = (ts_us - self.first_ts_us) / 1_000_000.0
        print(
            f"{rel_s:11.6f} {name:<14.14} {event.pid:<7d} {self.device:<9} {op} "
            f"{event.sector:<10d} {event.len:<7d} {que_ms:7.3f} {lat_ms:7.3f}",
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
