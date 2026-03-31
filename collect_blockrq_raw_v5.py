#!/usr/bin/env python3
"""
collect_blockrq_raw_v5.py

A biosnoop-like host I/O collector built on block raw tracepoints.
It emits a raw log compatible with the existing analyzer format:

    TIME(s) COMM PID DISK T SECTOR BYTES QUE(ms) LAT(ms)

Design goals:
- Avoid biosnoop's older hook mix when biosnoop stays silent.
- Use block raw tracepoints that are known to exist on this host.
- Keep output compatible with the existing analyzer.

Important notes:
- This version uses block_rq_issue -> block_rq_complete.
- QUE(ms) is emitted as 0.000 because block_rq_insert is not available on this host.
- LAT(ms) is reconstructed as block_rq_issue -> final block_rq_complete.
- block_rq_complete can fire for partial completions. This collector only emits
  when rq->bio == NULL, which is a reasonable proxy for final completion.
"""

from __future__ import annotations

import argparse
import ctypes as ct
import os
import signal
import sys
import time

from bcc import BPF  # type: ignore


BPF_PROGRAM = r'''
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/blk_types.h>

#ifndef DISK_NAME_LEN
#define DISK_NAME_LEN 32
#endif

struct stage_t {
    u64 issue_ns;
    u64 sector;
    u64 len;
    u64 cmd_flags;
    u32 pid;
    char disk_name[DISK_NAME_LEN];
    char comm[TASK_COMM_LEN];
};

struct event_t {
    u64 ts_ns;
    u64 delta_ns;
    u64 qdelta_ns;
    u64 sector;
    u64 len;
    u64 cmd_flags;
    u32 pid;
    char disk_name[DISK_NAME_LEN];
    char comm[TASK_COMM_LEN];
};

BPF_HASH(stages, struct request *, struct stage_t, 262144);
BPF_PERF_OUTPUT(events);

static __always_inline int target_match(const char *name)
{
    const char target[] = TARGET_DISK;
    int i;
#pragma unroll
    for (i = 0; i < sizeof(target); i++) {
        if (name[i] != target[i])
            return 0;
        if (target[i] == '\0')
            return 1;
    }
    return 1;
}

static __always_inline int load_disk_name(struct request *rq, char *out)
{
    struct gendisk *disk = rq->q ? rq->q->disk : NULL;
    if (!disk)
        return 0;
    bpf_probe_read_kernel_str(out, DISK_NAME_LEN, disk->disk_name);
    return out[0] != '\0';
}

RAW_TRACEPOINT_PROBE(block_rq_issue)
{
    struct request *rq;
    struct stage_t st = {};
    u64 now = bpf_ktime_get_ns();

    /* block_rq_issue(q, rq) */
    rq = (struct request *)ctx->args[1];
    if (!rq)
        return 0;

    st.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&st.comm, sizeof(st.comm));
    if (!load_disk_name(rq, st.disk_name))
        return 0;
    if (!target_match(st.disk_name))
        return 0;

    st.issue_ns = now;
    st.sector = rq->__sector;
    st.len = rq->__data_len;
    st.cmd_flags = rq->cmd_flags;
    stages.update(&rq, &st);
    return 0;
}

RAW_TRACEPOINT_PROBE(block_rq_complete)
{
    struct request *rq;
    struct stage_t *st;
    struct event_t ev = {};
    u64 now = bpf_ktime_get_ns();

    /* block_rq_complete(rq, error, nr_bytes) */
    rq = (struct request *)ctx->args[0];
    if (!rq)
        return 0;

    st = stages.lookup(&rq);
    if (!st)
        return 0;

    /* Emit only on final completion. */
    if (rq->bio != NULL)
        return 0;

    ev.ts_ns = now;
    ev.delta_ns = now - st->issue_ns;
    ev.qdelta_ns = 0;
    ev.sector = st->sector;
    ev.len = st->len;
    ev.cmd_flags = st->cmd_flags;
    ev.pid = st->pid;
    __builtin_memcpy(&ev.disk_name, st->disk_name, sizeof(ev.disk_name));
    __builtin_memcpy(&ev.comm, st->comm, sizeof(ev.comm));
    events.perf_submit(ctx, &ev, sizeof(ev));

    stages.delete(&rq);
    return 0;
}
'''


class Event(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_ulonglong),
        ("delta_ns", ct.c_ulonglong),
        ("qdelta_ns", ct.c_ulonglong),
        ("sector", ct.c_ulonglong),
        ("length", ct.c_ulonglong),
        ("cmd_flags", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("disk_name", ct.c_char * 32),
        ("comm", ct.c_char * 16),
    ]


REQ_OP_MASK = 0xFF
REQ_OP_READ = 0
REQ_OP_WRITE = 1


def decode_op(cmd_flags: int) -> str:
    op = cmd_flags & REQ_OP_MASK
    if op == REQ_OP_READ:
        return "R"
    if op == REQ_OP_WRITE:
        return "W"
    return "?"


class Collector:
    def __init__(self, device: str) -> None:
        self.device = device
        self.start_monotonic = time.monotonic()
        self.exiting = False
        text = BPF_PROGRAM.replace("TARGET_DISK", '"%s"' % device.replace('"', ''))
        self.b = BPF(text=text)
        self.b["events"].open_perf_buffer(self._handle_event, lost_cb=self._handle_lost, page_cnt=256)

    def _handle_lost(self, cpu: int, count: int) -> None:
        print(f"# WARN lost_events cpu={cpu} count={count}", file=sys.stderr, flush=True)

    def _handle_event(self, cpu: int, data: int, size: int) -> None:
        ev = ct.cast(data, ct.POINTER(Event)).contents
        rel_s = time.monotonic() - self.start_monotonic
        comm = bytes(ev.comm).split(b"\0", 1)[0].decode("utf-8", "replace")
        disk = bytes(ev.disk_name).split(b"\0", 1)[0].decode("utf-8", "replace")
        op = decode_op(int(ev.cmd_flags))
        q_ms = float(ev.qdelta_ns) / 1e6
        lat_ms = float(ev.delta_ns) / 1e6
        print(
            f"{rel_s:11.6f} {comm:<14.14} {ev.pid:<7d} {disk:<7.7} {op:<1} {ev.sector:<12d} {ev.length:<7d} {q_ms:8.3f} {lat_ms:8.3f}",
            flush=False,
        )

    def run(self) -> int:
        print("TIME(s)     COMM           PID     DISK    T SECTOR       BYTES   QUE(ms) LAT(ms)")
        sys.stdout.flush()
        while not self.exiting:
            try:
                self.b.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                self.exiting = True
            except Exception as exc:
                print(f"# ERROR perf_buffer_poll: {exc}", file=sys.stderr, flush=True)
                return 1
        return 0


collector: Collector | None = None


def handle_signal(signum, frame) -> None:  # type: ignore[no-untyped-def]
    global collector
    if collector is not None:
        collector.exiting = True


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect biosnoop-like block I/O events using block raw tracepoints.")
    parser.add_argument("-d", "--device", required=True, help="Disk name to trace, for example dm-8 or nvme0n1")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("This tool must run as root.", file=sys.stderr)
        return 1

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    global collector
    collector = Collector(device=args.device)
    return collector.run()


if __name__ == "__main__":
    raise SystemExit(main())
