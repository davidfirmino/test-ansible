#!/usr/bin/env python3
"""
collect_blockrq_raw_v3.py

A biosnoop-like host I/O collector built on block raw tracepoints.
It emits a raw log compatible with the existing analyzer format:

    TIME(s) COMM PID DISK T SECTOR BYTES QUE(ms) LAT(ms)

Design goals:
- Avoid biosnoop's older hook mix when biosnoop stays silent.
- Use block raw tracepoints and correlate requests by request pointer.
- Keep output compatible with the existing analyzer.

Important notes:
- QUE(ms) is reconstructed as block_rq_insert -> block_rq_issue.
- LAT(ms) is reconstructed as block_rq_issue -> final block_rq_complete.
- block_rq_complete can fire for partial completions. This collector only emits
  when rq->bio == NULL, which the kernel documents as the point where there is
  no further work left for the request.
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
    u64 insert_ns;
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
    struct gendisk *disk = rq->rq_disk;
    if (!disk)
        return 0;
    bpf_probe_read_kernel_str(out, DISK_NAME_LEN, disk->disk_name);
    return out[0] != '\0';
}

static __always_inline int ensure_stage(struct request *rq, struct stage_t **out)
{
    struct stage_t zero = {};
    struct stage_t *st = stages.lookup(&rq);
    if (st) {
        *out = st;
        return 1;
    }

    zero.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
    if (!load_disk_name(rq, zero.disk_name))
        return 0;
    if (!target_match(zero.disk_name))
        return 0;

    zero.sector = rq->__sector;
    zero.len = rq->__data_len;
    zero.cmd_flags = rq->cmd_flags;
    stages.update(&rq, &zero);
    st = stages.lookup(&rq);
    if (!st)
        return 0;

    *out = st;
    return 1;
}

static __always_inline int update_common(struct request *rq, struct stage_t *st)
{
    if (!st->disk_name[0]) {
        if (!load_disk_name(rq, st->disk_name))
            return 0;
    }
    if (!target_match(st->disk_name))
        return 0;

    if (!st->pid) {
        st->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&st->comm, sizeof(st->comm));
    }

    st->sector = rq->__sector;
    st->len = rq->__data_len;
    st->cmd_flags = rq->cmd_flags;
    return 1;
}

RAW_TRACEPOINT_PROBE(block_rq_insert)
{
    struct request *rq;
    struct stage_t *st;
    u64 now = bpf_ktime_get_ns();

    /* block_rq_insert(q, rq) */
    rq = (struct request *)ctx->args[1];
    if (!rq)
        return 0;

    if (!ensure_stage(rq, &st))
        return 0;
    if (!update_common(rq, st))
        return 0;

    st->insert_ns = now;
    return 0;
}

RAW_TRACEPOINT_PROBE(block_rq_issue)
{
    struct request *rq;
    struct stage_t *st;
    u64 now = bpf_ktime_get_ns();

    /* block_rq_issue(q, rq) */
    rq = (struct request *)ctx->args[1];
    if (!rq)
        return 0;

    if (!ensure_stage(rq, &st))
        return 0;
    if (!update_common(rq, st))
        return 0;

    st->issue_ns = now;
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

    if (!update_common(rq, st))
        goto cleanup;

    if (!st->issue_ns)
        goto cleanup;

    /* Only emit on final completion. The kernel docs say rq->bio == NULL means
     * there is no more work left for the request. */
    if (rq->bio != NULL)
        return 0;

    ev.ts_ns = now;
    ev.delta_ns = now - st->issue_ns;
    ev.qdelta_ns = st->insert_ns ? (st->issue_ns - st->insert_ns) : 0;
    ev.sector = st->sector;
    ev.len = st->len;
    ev.cmd_flags = st->cmd_flags;
    ev.pid = st->pid;
    __builtin_memcpy(&ev.disk_name, st->disk_name, sizeof(ev.disk_name));
    __builtin_memcpy(&ev.comm, st->comm, sizeof(ev.comm));
    events.perf_submit(ctx, &ev, sizeof(ev));

cleanup:
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
