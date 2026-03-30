#!/usr/bin/env bash
set -euo pipefail

DURATION=20
SAMPLE_DURATION=5
WORKLOAD_CMD=""
OUTDIR="/tmp/nvme_roce_trace_$(hostname)_$(date +%Y%m%d_%H%M%S)"
RUN_BIOSNOOP=1

usage() {
  cat <<'EOF'
Usage:
  sudo ./pure_nvme_roce_trace.sh [options]

Options:
  -t, --duration SEC          Main trace duration (default: 20)
  -s, --sample-duration SEC   Sample trace duration (default: 5)
  -c, --cmd 'COMMAND'         Optional workload command to run during capture
  -o, --outdir DIR            Output directory
      --no-biosnoop           Skip biosnoop comparison
  -h, --help                  Show help

Examples:
  sudo ./pure_nvme_roce_trace.sh

  sudo ./pure_nvme_roce_trace.sh -t 30 -s 8 \
    -c 'fio --name=trace --filename=/mnt/pure_storage/scratchfile \
        --size=1G --bs=4k --rw=randread --direct=1 --ioengine=libaio \
        --iodepth=32 --runtime=40 --time_based --group_reporting'

Notes:
  - Run as root.
  - Use --cmd only with a SAFE workload or a scratch file on the Pure-backed filesystem.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--duration) DURATION="$2"; shift 2 ;;
    -s|--sample-duration) SAMPLE_DURATION="$2"; shift 2 ;;
    -c|--cmd) WORKLOAD_CMD="$2"; shift 2 ;;
    -o|--outdir) OUTDIR="$2"; shift 2 ;;
    --no-biosnoop) RUN_BIOSNOOP=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

log() {
  printf '[%s] %s\n' "$(date '+%F %T')" "$*"
}

probe_exists() {
  local probe="$1"
  bpftrace -l "$probe" 2>/dev/null | grep -qx "$probe"
}

extract_scalar_map() {
  local file="$1"
  local mapname="$2"
  awk -v pat="^@"${mapname}":" '
    $0 ~ pat {
      gsub(/,/, "", $2)
      val = $2
    }
    END { print (val == "" ? 0 : val) }
  ' "$file"
}

if [[ $EUID -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

need bpftrace
need timeout
need lsblk
need findmnt
need awk
need grep
need sed
need uname

mkdir -p "$OUTDIR"

BT_NVME_SETUP=""
BT_NVME_COMPLETE=""
BT_BLK_ISSUE=""
BT_BLK_COMPLETE=""

if probe_exists 'tracepoint:nvme:nvme_setup_cmd'; then
  BT_NVME_SETUP='tracepoint:nvme:nvme_setup_cmd'
fi

if probe_exists 'tracepoint:nvme:nvme_complete_rq'; then
  BT_NVME_COMPLETE='tracepoint:nvme:nvme_complete_rq'
fi

if probe_exists 'tracepoint:block:block_rq_issue'; then
  BT_BLK_ISSUE='tracepoint:block:block_rq_issue'
elif probe_exists 'tracepoint:block:block_io_start'; then
  BT_BLK_ISSUE='tracepoint:block:block_io_start'
fi

if probe_exists 'tracepoint:block:block_rq_complete'; then
  BT_BLK_COMPLETE='tracepoint:block:block_rq_complete'
elif probe_exists 'tracepoint:block:block_io_done'; then
  BT_BLK_COMPLETE='tracepoint:block:block_io_done'
fi

BIOSNOOP_BIN=""
for x in biosnoop /usr/share/bcc/tools/biosnoop; do
  if command -v "$x" >/dev/null 2>&1; then
    BIOSNOOP_BIN="$(command -v "$x")"
    break
  elif [[ -x "$x" ]]; then
    BIOSNOOP_BIN="$x"
    break
  fi
done

log "Writing environment report to $OUTDIR/env.txt"
{
  echo "## date"
  date -Is
  echo

  echo "## uname -a"
  uname -a
  echo

  echo "## bpftrace --version"
  bpftrace --version || true
  echo

  echo "## rpm -q"
  rpm -q bcc-tools bcc bpftrace kernel-uek kernel-uek-core kernel-uek-devel kernel-core 2>/dev/null || true
  echo

  echo "## nvme list"
  if command -v nvme >/dev/null 2>&1; then
    nvme list || true
  else
    echo "nvme command not installed"
  fi
  echo

  echo "## nvme list-subsys"
  if command -v nvme >/dev/null 2>&1; then
    nvme list-subsys || true
  else
    echo "nvme command not installed"
  fi
  echo

  echo "## lsblk"
  lsblk -o NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL,SERIAL,PKNAME,ROTA
  echo

  echo "## findmnt"
  findmnt -R -o TARGET,SOURCE,FSTYPE,OPTIONS
  echo

  echo "## available NVMe tracepoints"
  bpftrace -l 'tracepoint:nvme:*' 2>/dev/null || true
  echo

  echo "## available block tracepoints of interest"
  bpftrace -l 'tracepoint:block:*' 2>/dev/null | egrep 'block_(rq_issue|rq_complete|io_start|io_done)' || true
  echo

  echo "## /proc/kallsyms blk_account"
  grep -E 'blk_account_io_start|__blk_account_io_start|blk_account_io_done|__blk_account_io_done' /proc/kallsyms || true
  echo
} > "$OUTDIR/env.txt" 2>&1

{
  dmesg -T 2>/dev/null | egrep -i 'nvme|rdma|roce|mlx|timeout|reset|abort|ana|multipath' | tail -n 300
} > "$OUTDIR/dmesg.txt" 2>&1 || true

WORKLOAD_PID=""

start_workload() {
  if [[ -n "$WORKLOAD_CMD" ]]; then
    log "Starting workload command"
    echo "$WORKLOAD_CMD" > "$OUTDIR/workload.command.txt"
    bash -lc "$WORKLOAD_CMD" > "$OUTDIR/workload.stdout.txt" 2> "$OUTDIR/workload.stderr.txt" &
    WORKLOAD_PID=$!
    sleep 1
  fi
}

stop_workload() {
  if [[ -n "${WORKLOAD_PID:-}" ]] && kill -0 "$WORKLOAD_PID" 2>/dev/null; then
    kill "$WORKLOAD_PID" 2>/dev/null || true
    wait "$WORKLOAD_PID" 2>/dev/null || true
  fi
}

trap stop_workload EXIT

COUNTS_BT="$OUTDIR/counts.bt"
SAMPLE_BT="$OUTDIR/sample.bt"
COUNTS_OUT="$OUTDIR/counts.txt"
SAMPLE_OUT="$OUTDIR/sample.txt"
BIOSNOOP_OUT="$OUTDIR/biosnoop.txt"
SUMMARY_OUT="$OUTDIR/summary.txt"

log "Generating bpftrace programs"

{
  printf 'BEGIN { printf("Tracing for %ss...\\n"); }\n' "$DURATION"

  if [[ -n "$BT_NVME_SETUP" ]]; then
    printf '%s { @nvme_setup = count(); }\n' "$BT_NVME_SETUP"
  fi

  if [[ -n "$BT_NVME_COMPLETE" ]]; then
    printf '%s {\n' "$BT_NVME_COMPLETE"
    printf '  @nvme_complete = count();\n'
    printf '  @nvme_status[args->status] = count();\n'
    printf '}\n'
  fi

  if [[ -n "$BT_BLK_ISSUE" ]]; then
    printf '%s { @blk_issue = count(); }\n' "$BT_BLK_ISSUE"
  fi

  if [[ -n "$BT_BLK_COMPLETE" ]]; then
    printf '%s { @blk_complete = count(); }\n' "$BT_BLK_COMPLETE"
  fi

  printf 'interval:s:%s { exit(); }\n' "$DURATION"
  printf 'END {\n'
  printf '  printf("\\n=== COUNTS ===\\n");\n'
  if [[ -n "$BT_NVME_SETUP" ]]; then
    printf '  print(@nvme_setup);\n'
  fi
  if [[ -n "$BT_NVME_COMPLETE" ]]; then
    printf '  print(@nvme_complete);\n'
    printf '  print(@nvme_status);\n'
  fi
  if [[ -n "$BT_BLK_ISSUE" ]]; then
    printf '  print(@blk_issue);\n'
  fi
  if [[ -n "$BT_BLK_COMPLETE" ]]; then
    printf '  print(@blk_complete);\n'
  fi
  printf '}\n'
} > "$COUNTS_BT"

{
  printf 'BEGIN { printf("Sampling for %ss...\\n"); }\n' "$SAMPLE_DURATION"

  if [[ -n "$BT_NVME_SETUP" ]]; then
    cat <<'EOF'
tracepoint:nvme:nvme_setup_cmd
{
  printf("NVME_SETUP pid=%d comm=%s disk=%s qid=%d cid=%u nsid=%u opcode=0x%x\n",
         pid, comm, str(args->disk), args->qid, args->cid, args->nsid, args->opcode);
}
EOF
  fi

  if [[ -n "$BT_NVME_COMPLETE" ]]; then
    cat <<'EOF'
tracepoint:nvme:nvme_complete_rq
{
  printf("NVME_DONE  pid=%d comm=%s disk=%s qid=%d cid=%u status=0x%x retries=%u\n",
         pid, comm, str(args->disk), args->qid, args->cid, args->status, args->retries);
}
EOF
  fi

  if [[ -n "$BT_BLK_ISSUE" ]]; then
    cat <<EOF
$BT_BLK_ISSUE
{
  printf("BLK_ISSUE pid=%d comm=%s cpu=%d\n", pid, comm, cpu);
}
EOF
  fi

  if [[ -n "$BT_BLK_COMPLETE" ]]; then
    cat <<EOF
$BT_BLK_COMPLETE
{
  printf("BLK_DONE  pid=%d comm=%s cpu=%d\n", pid, comm, cpu);
}
EOF
  fi

  printf 'interval:s:%s { exit(); }\n' "$SAMPLE_DURATION"
} > "$SAMPLE_BT"

start_workload

log "Running count trace"
bpftrace "$COUNTS_BT" > "$COUNTS_OUT" 2>&1 || true

log "Running sample trace"
bpftrace "$SAMPLE_BT" > "$SAMPLE_OUT" 2>&1 || true

if [[ "$RUN_BIOSNOOP" -eq 1 && -n "$BIOSNOOP_BIN" ]]; then
  log "Running biosnoop comparison"
  timeout "$SAMPLE_DURATION" "$BIOSNOOP_BIN" > "$BIOSNOOP_OUT" 2>&1 || true
else
  echo "biosnoop skipped" > "$BIOSNOOP_OUT"
fi

NVME_SETUP_N=$(extract_scalar_map "$COUNTS_OUT" "nvme_setup")
NVME_COMPLETE_N=$(extract_scalar_map "$COUNTS_OUT" "nvme_complete")
BLK_ISSUE_N=$(extract_scalar_map "$COUNTS_OUT" "blk_issue")
BLK_COMPLETE_N=$(extract_scalar_map "$COUNTS_OUT" "blk_complete")

BIOSNOOP_LINES=0
if [[ -f "$BIOSNOOP_OUT" ]]; then
  BIOSNOOP_LINES=$(grep -Evc '(^$|Tracing block device I/O|TIME|COMM|PID|START)' "$BIOSNOOP_OUT" || true)
fi

{
  echo "Output directory: $OUTDIR"
  echo
  echo "Selected probes:"
  echo "  NVMe setup:     ${BT_NVME_SETUP:-not found}"
  echo "  NVMe complete:  ${BT_NVME_COMPLETE:-not found}"
  echo "  Block issue:    ${BT_BLK_ISSUE:-not found}"
  echo "  Block complete: ${BT_BLK_COMPLETE:-not found}"
  echo
  echo "Counts:"
  echo "  nvme_setup     = $NVME_SETUP_N"
  echo "  nvme_complete  = $NVME_COMPLETE_N"
  echo "  blk_issue      = $BLK_ISSUE_N"
  echo "  blk_complete   = $BLK_COMPLETE_N"
  echo "  biosnoop_lines = $BIOSNOOP_LINES"
  echo

  if (( NVME_SETUP_N > 0 && NVME_COMPLETE_N > 0 && BLK_ISSUE_N == 0 && BLK_COMPLETE_N == 0 )); then
    echo "Diagnosis:"
    echo "  NVMe tracepoints saw real I/O submission/completion, but the chosen block tracepoints saw nothing."
    echo "  This strongly suggests the host sees the I/O at the NVMe layer, while your local biosnoop/block hook path is not matching this storage path."
  elif (( (BLK_ISSUE_N > 0 || BLK_COMPLETE_N > 0) && BIOSNOOP_LINES == 0 )); then
    echo "Diagnosis:"
    echo "  The block layer saw I/O, but biosnoop stayed silent."
    echo "  This strongly suggests a biosnoop/BCC attach or compatibility problem on this host."
  elif (( NVME_SETUP_N > 0 && NVME_COMPLETE_N == 0 )); then
    echo "Diagnosis:"
    echo "  NVMe submissions appeared, but no completions were seen during the window."
    echo "  Check dmesg.txt for timeout/reset/abort activity."
  elif (( NVME_SETUP_N == 0 && NVME_COMPLETE_N == 0 && BLK_ISSUE_N == 0 && BLK_COMPLETE_N == 0 )); then
    echo "Diagnosis:"
    echo "  No I/O reached the traced layers during the capture window."
    echo "  Either the workload missed the Pure-backed path, used cache/non-direct I/O, or probe attachment failed."
  else
    echo "Diagnosis:"
    echo "  More than one layer saw I/O."
    if (( BIOSNOOP_LINES > 0 )); then
      echo "  biosnoop also printed events."
    else
      echo "  biosnoop still did not print events, which points back to biosnoop itself."
    fi
  fi

  echo
  echo "Generated files:"
  ls -1 "$OUTDIR"
} | tee "$SUMMARY_OUT"

log "Done. Read:"
log "  $SUMMARY_OUT"
log "  $COUNTS_OUT"
log "  $SAMPLE_OUT"
log "  $BIOSNOOP_OUT"
log "  $OUTDIR/dmesg.txt"
