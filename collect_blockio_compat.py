#!/usr/bin/env python3
"""
collect_blockio_compat.py

A biosnoop-compatible raw collector for host-side block I/O latency.

Goals:
- Produce a raw log compatible with the existing analyzer pipeline.
- Avoid raw tracepoint attachment.
- Follow the same strategy used by upstream biosnoop:
  * Prefer block tracepoints block_io_start/block_io_done when available.
  * Fall back to kprobes on __blk_account_io_start/blk_account_io_start,
    blk_start_request/blk_mq_start_request, and
    __blk_account_io_done/blk_account_io_done.

Output format:
TIME(s) COMM PID DISK T SECTOR BYTES QUE(ms) LAT(ms)
"""

from __future__ import print_function

import argparse
import ctypes as ct
import os
import signal
import sys
import time

from bcc import BPF


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


BPF_TEXT = r'''
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

struct start_req_t {
    u64 ts;
    u64 data_len;
};

struct val_t {
    u64 ts;
    u32 pid;
    char name[TASK_COMM_LEN];
};

struct hash_key {
    dev_t dev;
    u32 rwflag;
    sector_t sector;
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

BPF_HASH(start, struct hash_key, struct start_req_t);
BPF_HASH(infobyreq, struct hash_key, struct val_t);
BPF_PERF_OUTPUT(events);

static dev_t ddevt(struct gendisk *disk) {
    return (disk->major << 20) | disk->first_minor;
}

static int get_rwflag(u32 cmd_flags) {
#ifdef REQ_WRITE
    return !!(cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    return !!((cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    return !!((cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif
}

#define RWBS_LEN 8
static int get_rwflag_tp(char *rwbs) {
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

static int __trace_pid_start(struct hash_key key)
{
    DISK_FILTER
    struct val_t val = {};
    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = bpf_get_current_pid_tgid() >> 32;
        val.ts = bpf_ktime_get_ns();
        infobyreq.update(&key, &val);
    }
    return 0;
}

int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector,
    };
    return __trace_pid_start(key);
}

int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector,
    };
    DISK_FILTER
    struct start_req_t start_req = {
        .ts = bpf_ktime_get_ns(),
        .data_len = req->__data_len,
    };
    start.update(&key, &start_req);
    return 0;
}

static int __trace_req_completion(void *ctx, struct hash_key key)
{
    struct start_req_t *startp;
    struct val_t *valp;
    struct data_t data = {};
    u64 ts;

    startp = start.lookup(&key);
    if (startp == 0) {
        return 0;
    }

    ts = bpf_ktime_get_ns();
    data.delta = ts - startp->ts;
    data.ts = ts / 1000;
    data.qdelta = 0;
    data.len = startp->data_len;

    valp = infobyreq.lookup(&key);
    if (valp == 0) {
        data.name[0] = '?';
        data.name[1] = 0;
    } else {
        data.qdelta = startp->ts - valp->ts;
        data.pid = valp->pid;
        data.sector = key.sector;
        data.dev = key.dev;
        bpf_probe_read_kernel(&data.name, sizeof(data.name), valp->name);
    }

    data.rwflag = key.rwflag;
    events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&key);
    infobyreq.delete(&key);
    return 0;
}

int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector,
    };
    return __trace_req_completion(ctx, key);
}
'''

TP_START_TEXT = r'''
TRACEPOINT_PROBE(block, block_io_start)
{
    struct hash_key key = {
        .dev = args->dev,
        .rwflag = get_rwflag_tp(args->rwbs),
        .sector = args->sector,
    };
    return __trace_pid_start(key);
}
'''

TP_DONE_TEXT = r'''
TRACEPOINT_PROBE(block, block_io_done)
{
    struct hash_key key = {
        .dev = args->dev,
        .rwflag = get_rwflag_tp(args->rwbs),
        .sector = args->sector,
    };
    return __trace_req_completion(args, key);
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


class Collector:
    def __init__(self, device: str):
        self.device = device
        self.dev_t = get_disk_dev_t(device)
        self.first_ts_us = None
        self.exiting = False

        bpf_text = BPF_TEXT

        # request.rq_disk was removed on newer kernels; upstream biosnoop uses q->disk fallback.
        if hasattr(BPF, "kernel_struct_has_field") and BPF.kernel_struct_has_field(b"request", b"rq_disk") == 1:
            bpf_text = bpf_text.replace("__RQ_DISK__", "rq_disk")
        else:
            bpf_text = bpf_text.replace("__RQ_DISK__", "q->disk")

        disk_filter = f'''
        if (key.dev != {self.dev_t}) {{
            return 0;
        }}
        '''
        bpf_text = bpf_text.replace("DISK_FILTER", disk_filter)

        self.tp_start = tracepoint_exists("block", "block_io_start")
        self.tp_done = tracepoint_exists("block", "block_io_done")
        if self.tp_start:
            bpf_text += TP_START_TEXT
        if self.tp_done:
            bpf_text += TP_DONE_TEXT

        self.b = BPF(text=bpf_text)
        self._attach()
        self.b["events"].open_perf_buffer(self._handle_event, page_cnt=64)

    def _attach(self) -> None:
        if not self.tp_start:
            if BPF.get_kprobe_functions(b"__blk_account_io_start"):
                self.b.attach_kprobe(event="__blk_account_io_start", fn_name="trace_pid_start")
            elif BPF.get_kprobe_functions(b"blk_account_io_start"):
                self.b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
            else:
                raise RuntimeError("No block I/O start tracepoint or kprobe found")

        if BPF.get_kprobe_functions(b"blk_start_request"):
            self.b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
        if BPF.get_kprobe_functions(b"blk_mq_start_request"):
            self.b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
        else:
            raise RuntimeError("blk_mq_start_request not found")

        if not self.tp_done:
            if BPF.get_kprobe_functions(b"__blk_account_io_done"):
                self.b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_req_completion")
            elif BPF.get_kprobe_functions(b"blk_account_io_done"):
                self.b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_completion")
            else:
                raise RuntimeError("No block I/O done tracepoint or kprobe found")

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
    parser = argparse.ArgumentParser(description="Collect biosnoop-compatible block I/O raw data")
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
