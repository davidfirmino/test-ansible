#!/usr/bin/env python3
"""
san_debug_analyzer.py v3.11 (Workload Profile + Dynamic HTML Name)

Offline analyzer for SAN debug collections produced by collect_san_debug_v3.3x+ (Bash).

Usage:
    python3 san_debug_analyzer.py /path/to/collection.zip --html

Features:
  - [NEW] Workload Profile: Read/Write Ratio & Global Avg Block Size.
  - [VISUAL] Interactive HTML Dashboard (filename matches ZIP name).
  - [I/O] Sub-millisecond analysis & Granular Tail Distribution.
  - [I/O] Granular IO Size Buckets.
  - [NET] Clean TCP & Switch analysis.

Requirements:
  - Python 3.6+
  - Standard library only.
"""

import argparse
import json
import math
import os
import statistics
import tempfile
import zipfile
import shutil
import re
from datetime import datetime

# ==========================================
# FILE HELPERS
# ==========================================

def open_collection(path: str):
    if os.path.isdir(path):
        return path, None
    if not zipfile.is_zipfile(path):
        raise ValueError(f"'{path}' is neither a directory nor a valid ZIP file.")
    tmpdir = tempfile.mkdtemp(prefix="san_debug_")
    try:
        with zipfile.ZipFile(path, "r") as zf:
            zf.extractall(tmpdir)
    except Exception as e:
        shutil.rmtree(tmpdir)
        raise IOError(f"Failed to extract ZIP: {e}")
    return tmpdir, tmpdir

def find_file(base_dir: str, contains: str, suffix: str = None):
    if not os.path.exists(base_dir):
        return None
    for name in os.listdir(base_dir):
        if contains in name and (suffix is None or name.endswith(suffix)):
            return os.path.join(base_dir, name)
    return None

def load_text_lines(path: str):
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [line.rstrip("\n") for line in f]
    except Exception:
        return []

def load_json(path: str):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def format_ts(ts: int):
    if ts is None:
        return "N/A"
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

# ==========================================
# STATS HELPERS
# ==========================================

def percentile(values, p):
    if not values:
        return 0.0
    values_sorted = sorted(values)
    n = len(values_sorted)
    k = (n - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return values_sorted[int(k)]
    d0 = values_sorted[f] * (c - k)
    d1 = values_sorted[c] * (k - f)
    return d0 + d1

# ==========================================
# HTML GENERATOR (V3.11 with Workload Profile)
# ==========================================

def generate_html_report(output_path, bio, io, tcp, host_vm, vol_vm, sws, heuristics, metadata):
    # Calculate R/W Mix
    total = bio['all']['total_ios'] or 1
    r_count = bio['reads']['total_ios']
    w_count = bio['writes']['total_ios']
    r_pct = (r_count / total) * 100
    w_pct = (w_count / total) * 100
    
    # Calculate Global Avg Block Size
    total_bytes = bio['all']['total_bytes']
    avg_bs = total_bytes / total if total > 0 else 0
    avg_bs_str = f"{int(avg_bs)} B ({avg_bs/1024:.1f} KiB)"

    css = """
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; color: #343a40; margin: 0; padding: 20px; }
    .container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 8px; }
    .header { border-bottom: 2px solid #e9ecef; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
    .header h1 { margin: 0; font-size: 24px; color: #2c3e50; }
    .header .meta { text-align: right; font-size: 14px; color: #6c757d; }
    
    .alert-box { background-color: #fff3cd; color: #856404; padding: 15px; border-left: 5px solid #ffeeba; margin-bottom: 30px; border-radius: 4px; font-size: 15px; }
    
    .section-title { font-size: 18px; font-weight: 600; color: #495057; margin-bottom: 15px; border-left: 4px solid #007bff; padding-left: 10px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; margin-bottom: 40px; }
    .card { background: #fff; border: 1px solid #e9ecef; border-radius: 6px; padding: 20px; }
    .card h3 { margin-top: 0; border-bottom: 1px solid #f0f0f0; padding-bottom: 10px; font-size: 16px; color: #333; display: flex; justify-content: space-between; }
    
    table.metrics { width: 100%; border-collapse: collapse; font-size: 14px; }
    table.metrics td { padding: 8px 0; border-bottom: 1px solid #f8f9fa; }
    table.metrics tr:last-child td { border-bottom: none; }
    .val { font-weight: 600; float: right; color: #212529; }
    
    /* Bars */
    .bar-row { margin-bottom: 8px; font-size: 13px; }
    .bar-meta { display: flex; justify-content: space-between; margin-bottom: 3px; }
    .progress-track { background-color: #e9ecef; height: 12px; border-radius: 6px; overflow: hidden; }
    .progress-fill { height: 100%; border-radius: 6px; }
    
    /* Workload Mix Bar */
    .mix-bar { display: flex; height: 24px; width: 100%; border-radius: 6px; overflow: hidden; margin: 10px 0; font-size: 12px; font-weight: bold; color: white; }
    .mix-read { background-color: #17a2b8; display: flex; align-items: center; justify-content: center; }
    .mix-write { background-color: #e83e8c; display: flex; align-items: center; justify-content: center; }
    
    /* Colors */
    .c-green { background-color: #28a745; }
    .c-blue { background-color: #17a2b8; }
    .c-yellow { background-color: #ffc107; }
    .c-red { background-color: #dc3545; }
    .c-info { background-color: #007bff; }

    .tag { padding: 2px 6px; font-size: 11px; border-radius: 4px; color: #fff; text-transform: uppercase; }
    .tag-clean { background-color: #28a745; }
    .tag-err { background-color: #dc3545; }
    .tag-warn { background-color: #ffc107; color: #333; }
    """

    def render_io_bars(stats):
        html = ""
        total = stats["total_ios"] or 1
        mapping = [
            ("<= 1 ms", "count_lt_1ms", "c-green"),
            ("> 1 ms", "count_1ms", "c-blue"),
            ("> 5 ms", "count_5ms", "c-yellow"),
            ("> 20 ms", "count_20ms", "c-red"),
            ("> 50 ms", "count_50ms", "c-red"),
        ]
        for label, key, color in mapping:
            val = stats.get(key, 0)
            pct = (val / total) * 100.0
            if val == 0 and key != "count_lt_1ms": continue
            html += f"""
            <div class="bar-row">
                <div class="bar-meta"><span>{label}</span> <span>{val} ({pct:.2f}%)</span></div>
                <div class="progress-track"><div class="progress-fill {color}" style="width: {pct}%"></div></div>
            </div>"""
        return html

    def render_size_bars(stats):
        html = ""
        buckets = stats["buckets"]
        max_c = 0
        for b in buckets.values():
            if b["count"] > max_c: max_c = b["count"]
        max_c = max_c or 1
        order = ["<=1", "1-2", "2-3", "3-4", "4-5", "5-10", "10-20", "20-50", ">50"]
        for bkey in order:
            b = buckets[bkey]
            if b["count"] == 0: continue
            width = (b["count"] / max_c) * 100.0
            avg_kb = (b["bytes"] / b["count"]) / 1024 if b["count"] else 0
            html += f"""
            <div class="bar-row">
                <div class="bar-meta"><span>{bkey} ms</span> <span>{b['count']} IOs | <b>{avg_kb:.1f} KiB</b></span></div>
                <div class="progress-track"><div class="progress-fill c-info" style="width: {width}%"></div></div>
            </div>"""
        return html

    sw_html = ""
    if not sws: sw_html = "<p>No switch data.</p>"
    else:
        for s in sws:
            badge = '<span class="tag tag-clean">CLEAN</span>'
            if s['errors']>0 or s['drops_out']>0: badge = '<span class="tag tag-err">ERRORS</span>'
            elif s['util_in_pct']>90: badge = '<span class="tag tag-warn">SATURATED</span>'
            sw_html += f"""
            <div class="card">
                <h3>{s['iface']} &rarr; {s['switch']}:{s['port']} {badge}</h3>
                <table class="metrics">
                    <tr><td>Speed</td><td class="val">{s['speed']/1000:.1f}G</td></tr>
                    <tr><td>RX/TX Util</td><td class="val">{s['util_in_pct']:.0f}% / {s['util_out_pct']:.0f}%</td></tr>
                    <tr><td>Drops/Err</td><td class="val">{int(s['drops_in'])}/{int(s['drops_out'])} / {int(s['errors'])}</td></tr>
                </table>
            </div>"""

    body = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>SAN Debug Report</title><style>{css}</style></head>
    <body>
        <div class="container">
            <div class="header">
                <div><h1>SAN Debug Analysis</h1><small>{metadata['source']}</small></div>
                <div class="meta"><strong>{metadata['device']}</strong><br>{metadata['time_window']}</div>
            </div>
            <div class="alert-box"><strong>Heuristics:</strong> {heuristics}</div>

            <div class="section-title">Workload Profile</div>
            <div class="card" style="margin-bottom:40px;">
                <h3>Profile Summary <small>Total IOs: {total} | Global Avg Block Size: {avg_bs_str}</small></h3>
                <div class="mix-bar">
                    <div class="mix-read" style="width: {r_pct}%">READ {r_pct:.1f}%</div>
                    <div class="mix-write" style="width: {w_pct}%">WRITE {w_pct:.1f}%</div>
                </div>
            </div>

            <div class="section-title">Host I/O Latency</div>
            <div class="grid">
                <div class="card"><h3>ALL OPERATIONS</h3>{render_io_bars(bio['all'])}
                    <div style="margin-top:10px;font-size:12px;border-top:1px solid #eee;padding-top:5px;">
                    <strong>P99.99:</strong> {bio['all']['p9999']:.3f} ms <span style="float:right"><strong>Max:</strong> {bio['all']['max_lat_ms']:.2f} ms</span></div>
                </div>
                <div class="card"><h3>READS</h3>{render_io_bars(bio['reads'])}
                    <div style="margin-top:10px;font-size:12px;border-top:1px solid #eee;padding-top:5px;">
                    <strong>P99.99:</strong> {bio['reads']['p9999']:.3f} ms</div>
                </div>
                <div class="card"><h3>WRITES</h3>{render_io_bars(bio['writes'])}
                    <div style="margin-top:10px;font-size:12px;border-top:1px solid #eee;padding-top:5px;">
                    <strong>P99.99:</strong> {bio['writes']['p9999']:.3f} ms</div>
                </div>
            </div>

            <div class="section-title">IO Size Impact</div>
            <div class="grid">
                 <div class="card"><h3>ALL OPS</h3>{render_size_bars(bio['all'])}</div>
                 <div class="card"><h3>READS</h3>{render_size_bars(bio['reads'])}</div>
                 <div class="card"><h3>WRITES</h3>{render_size_bars(bio['writes'])}</div>
            </div>

            <div class="section-title">Infrastructure</div>
            <div class="grid">
                <div class="card"><h3>Host TCP/Kernel</h3>
                    <table class="metrics">
                        <tr><td>Avg r_await</td><td class="val">{io['avg_r_await_ms']:.3f} ms</td></tr>
                        <tr><td>TCP Retransmits</td><td class="val">{tcp.get('TCPRetransSegs',0)}</td></tr>
                        <tr><td>TCP Out-of-Order</td><td class="val">{tcp.get('TCPOFOQueue',0)}</td></tr>
                        <tr><td>TCP DSACK Recv</td><td class="val">{tcp.get('TCPDSACKRecvSegs',0)}</td></tr>
                    </table>
                </div>
                {sw_html}
            </div>
            
            <div class="section-title">Storage Array (Pure)</div>
            <div class="grid">
                <div class="card"><h3>Host: {host_vm['host']}</h3>
                    <table class="metrics">
                        <tr><td>SAN Latency (R/W)</td><td class="val">{host_vm['san_read_ms']:.2f} / {host_vm['san_write_ms']:.2f} ms</td></tr>
                        <tr><td>Service Latency (R/W)</td><td class="val">{host_vm['svc_read_ms']:.2f} / {host_vm['svc_write_ms']:.2f} ms</td></tr>
                    </table>
                </div>
                <div class="card"><h3>Vol: {vol_vm['volume']}</h3>
                    <table class="metrics">
                        <tr><td>SAN Latency (R/W)</td><td class="val">{vol_vm['san_read_ms']:.2f} / {vol_vm['san_write_ms']:.2f} ms</td></tr>
                        <tr><td>Service Latency (R/W)</td><td class="val">{vol_vm['svc_read_ms']:.2f} / {vol_vm['svc_write_ms']:.2f} ms</td></tr>
                    </table>
                </div>
            </div>
        </div>
    </body></html>
    """
    try:
        with open(output_path, "w", encoding="utf-8") as f: f.write(body)
        print(f"\n[REPORT] HTML Dashboard generated: {output_path}")
        return True
    except Exception as e: print(f"[!] Failed HTML: {e}"); return False

# ==========================================
# BIOSNOOP ANALYZER (UPDATED v3.11 with Total Bytes)
# ==========================================

def analyze_biosnoop_raw(path: str):
    lines = load_text_lines(path)
    def make_stats():
        return {
            "total_ios": 0, "total_bytes": 0, "max_lat_ms": 0.0, "max_que_ms": 0.0,
            "count_lt_1ms": 0, "count_1ms": 0, "count_2ms": 0, "count_3ms": 0, 
            "count_4ms": 0, "count_5ms": 0, "count_10ms": 0, "count_20ms": 0, "count_50ms": 0,
            "avg": 0.0, "p50": 0.0, "p90": 0.0, "p95": 0.0, "p99": 0.0, "p999": 0.0, "p9999": 0.0,
            "buckets": {
                "<=1": {"count":0,"bytes":0}, "1-2": {"count":0,"bytes":0}, "2-3": {"count":0,"bytes":0},
                "3-4": {"count":0,"bytes":0}, "4-5": {"count":0,"bytes":0}, "5-10": {"count":0,"bytes":0},
                "10-20": {"count":0,"bytes":0}, "20-50": {"count":0,"bytes":0}, ">50": {"count":0,"bytes":0},
            },
        }

    s_all, s_read, s_write = make_stats(), make_stats(), make_stats()
    if len(lines) <= 1: return {"all": s_all, "reads": s_read, "writes": s_write}
    l_all, l_read, l_write = [], [], []

    def bucket_key(lat):
        if lat <= 1.0: return "<=1"
        if lat <= 2.0: return "1-2"
        if lat <= 3.0: return "2-3"
        if lat <= 4.0: return "3-4"
        if lat <= 5.0: return "4-5"
        if lat <= 10.0: return "5-10"
        if lat <= 20.0: return "10-20"
        if lat <= 50.0: return "20-50"
        return ">50"

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 9: continue
        try:
            op = parts[4]
            byts = int(parts[6])
            que = float(parts[-2])
            lat = float(parts[-1])
        except: continue

        def update(s, l_list):
            s["total_ios"] += 1
            s["total_bytes"] += byts
            l_list.append(lat)
            if lat > s["max_lat_ms"]: s["max_lat_ms"] = lat
            if lat > 5.0 and que > s["max_que_ms"]: s["max_que_ms"] = que
            
            if lat <= 1.0: s["count_lt_1ms"] += 1
            if lat > 1.0: s["count_1ms"] += 1
            if lat > 2.0: s["count_2ms"] += 1
            if lat > 3.0: s["count_3ms"] += 1
            if lat > 4.0: s["count_4ms"] += 1
            if lat > 5.0: s["count_5ms"] += 1
            if lat > 10.0: s["count_10ms"] += 1
            if lat > 20.0: s["count_20ms"] += 1
            if lat > 50.0: s["count_50ms"] += 1
            
            b = s["buckets"][bucket_key(lat)]
            b["count"] += 1
            b["bytes"] += byts

        update(s_all, l_all)
        if op.upper().startswith("R"): update(s_read, l_read)
        elif op.upper().startswith("W"): update(s_write, l_write)

    def finalize(s, l_list):
        if s["total_ios"] > 0 and l_list:
            s["avg"] = statistics.mean(l_list)
            s["p50"] = percentile(l_list, 50)
            s["p90"] = percentile(l_list, 90)
            s["p95"] = percentile(l_list, 95)
            s["p99"] = percentile(l_list, 99)
            s["p999"] = percentile(l_list, 99.9)
            s["p9999"] = percentile(l_list, 99.99)
        return s

    return {"all": finalize(s_all, l_all), "reads": finalize(s_read, l_read), "writes": finalize(s_write, l_write)}

# ==========================================
# OTHER ANALYZERS
# ==========================================

def analyze_iostat(path: str, dev_hint: str = None):
    lines = load_text_lines(path)
    stats = {"device": dev_hint or "unknown", "avg_r_await_ms": None}
    r_sum, count, col_idx, parsing = 0.0, 0, {}, False
    target = dev_hint
    for line in lines:
        parts = line.split()
        if not parts: continue
        if parts[0] == "Device":
            col_idx = {name: i for i, name in enumerate(parts)}
            parsing = True; continue
        if not parsing: continue
        if not target: target = parts[0]
        elif parts[0] != target: continue
        try:
            val = float(parts[col_idx["r_await"]]) if "r_await" in col_idx else float(parts[9])
            r_sum += val; count += 1
        except: pass
    if count: stats["avg_r_await_ms"] = r_sum / count
    stats["device"] = target
    return stats

def analyze_tcpext(s_path, e_path):
    def parse(p):
        d = {}
        lines = load_text_lines(p)
        head = []
        for l in lines:
            if l.startswith("TcpExt:"):
                pts = l.split()
                if not head: head = pts[1:]
                else: 
                    for k,v in zip(head, pts[1:]): 
                        try: d[k]=int(v) 
                        except: pass
                    head=[]
        return d
    s, e = parse(s_path), parse(e_path)
    deltas = {}
    keys = ["TCPOFOQueue", "TCPDSACKRecvSegs", "TCPDSACKSendSegs", "TCPRetransSegs"]
    for k in keys:
        deltas[k] = max(0, e.get(k,0) - s.get(k,0))
    return deltas

def _load_vm(path, key):
    d = load_json(path)
    if not d: return None, None
    try: 
        res = d["data"]["result"][0]
        return res["metric"].get(key, "unknown"), float(res["value"][1])
    except: return None, None

def analyze_pure_metrics(base_dir, kind, lbl_key, name_filter):
    stats = {"name": name_filter or "N/A"}
    for m in ["san_read_ms", "san_write_ms", "service_read_ms", "service_write_ms", "queue_read_ms", "queue_write_ms"]:
        _, v = _load_vm(find_file(base_dir, f"vm_{kind}_{m}", ".json"), lbl_key)
        stats[m.replace("service", "svc")] = v 
    
    # IO Size (missing from previous brevity)
    _, ior = _load_vm(find_file(base_dir, f"vm_{kind}_iosize_read_bytes", ".json"), lbl_key)
    _, iow = _load_vm(find_file(base_dir, f"vm_{kind}_iosize_write_bytes", ".json"), lbl_key)
    stats["io_size_read"] = ior
    stats["io_size_write"] = iow

    # Load label
    l, _ = _load_vm(find_file(base_dir, f"vm_{kind}_san_read_ms", ".json"), lbl_key)
    if l: stats["name"] = l
    return stats

def analyze_switch(base_dir, dur):
    res = []
    if not os.path.exists(base_dir): return res
    ifaces = set()
    for f in os.listdir(base_dir):
        if "vm_switch_" in f and ".json" in f:
            m = re.search(r"vm_switch_.*_([a-zA-Z0-9\.]+)\.json", f)
            if m: ifaces.add(m.group(1))
    for iface in ifaces:
        speed = 0
        slines = load_text_lines(find_file(base_dir, "nic_status", ".log"))
        for l in slines: 
            if l.startswith(f"{iface} "): 
                m = re.search(r"Speed:\s*(\d+)Mb/s", l)
                if m: speed = int(m.group(1))
        
        m = {"iface": iface, "switch": "N/A", "port": "N/A", "speed": speed, 
             "drops_in":0, "drops_out":0, "errors":0, "util_in_pct":0, "util_out_pct":0, "gbps_in":0, "gbps_out":0}
        
        ed = load_json(find_file(base_dir, f"vm_switch_errors_{iface}", ".json"))
        if ed:
            for i in ed.get("data",{}).get("result",[]):
                m["switch"] = i["metric"].get("instance", m["switch"]).split(".")[0]
                m["port"] = i["metric"].get("intf", m["port"])
                v = float(i["value"][1])
                nm = i["metric"].get("__name__","")
                if "discard" in nm: 
                    if "receive" in nm: m["drops_in"]+=v 
                    else: m["drops_out"]+=v
                elif "errs" in nm: m["errors"]+=v
        
        bd = load_json(find_file(base_dir, f"vm_switch_bytes_{iface}", ".json"))
        bin, bout = 0, 0
        if bd:
             for i in bd.get("data",{}).get("result",[]):
                nm = i["metric"].get("__name__","")
                v = float(i["value"][1])
                if "receive" in nm: bin += v
                else: bout += v
        if dur > 0:
            m["gbps_in"] = (bin * 8 / dur) / 1e9
            m["gbps_out"] = (bout * 8 / dur) / 1e9
            if speed > 0:
                m["util_in_pct"] = (bin*8/dur)/(speed*1e6)*100
                m["util_out_pct"] = (bout*8/dur)/(speed*1e6)*100
        res.append(m)
    return res

def infer_heuristics(bio, io, tcp, host_vm, sw_list):
    msgs = []
    
    h_lat = io.get("avg_r_await_ms")
    # Calculate Array Total Latency manually for heuristic check if not present
    arr_lat = None
    if host_vm.get("san_read_ms") is not None:
        arr_lat = host_vm["san_read_ms"] + host_vm["svc_read_ms"] + host_vm["queue_read_ms"]
        
    if h_lat is not None and arr_lat is not None and (h_lat - arr_lat > 1.0):
        msgs.append(f"Host read latency > Array read latency (Delta={h_lat - arr_lat:.2f} ms). OS overhead.")

    san_r = host_vm.get("san_read_ms")
    svc_r = host_vm.get("svc_read_ms")
    if san_r and svc_r and san_r > 2.0 and svc_r < 1.0:
        msgs.append("SAN read latency > 2ms (Congestion).")
    
    if bio["all"]["count_50ms"] > 0:
        msgs.append("CRITICAL: I/Os > 50 ms observed.")
        
    tcp_tot = tcp.get("TCPOFOQueue",0) + tcp.get("TCPDSACKRecvSegs",0) + tcp.get("TCPRetransSegs",0)
    if tcp_tot > 0: msgs.append(f"TCP anomalies (Retrans/OFO/DSACK={tcp_tot}).")

    if not msgs: return "No obvious anomalies detected in this window."
    return " | ".join(msgs)

# ==========================================
# MAIN
# ==========================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--pure-host-name", default=None)
    parser.add_argument("--pure-volume-name", default=None)
    parser.add_argument("--html", action="store_true")
    args = parser.parse_args()

    try: base_dir, tmpdir = open_collection(args.path)
    except Exception as e: print(e); return

    try:
        bio = analyze_biosnoop_raw(find_file(base_dir, "biosnoop_raw_", ".log"))
        io = analyze_iostat(find_file(base_dir, "iostat_", ".log"))
        tcp = analyze_tcpext(find_file(base_dir, "tcpext_start", ".log"), find_file(base_dir, "tcpext_end", ".log"))
        
        tw = find_file(base_dir, "time_window", ".txt")
        st, et, ph, pv = None, None, None, None
        if tw:
            for l in load_text_lines(tw):
                if "START_TS=" in l: st = int(l.split("=",1)[1])
                elif "END_TS=" in l: et = int(l.split("=",1)[1])
                elif "PURE_HOST_NAME=" in l: ph = l.split("=",1)[1]
                elif "PURE_VOLUME_NAME=" in l: pv = l.split("=",1)[1]
        
        dur = (et - st) if (st and et) else 300
        host_vm = analyze_pure_metrics(base_dir, "host", "host", ph or args.pure_host_name)
        host_vm["host"] = host_vm.pop("name")
        vol_vm = analyze_pure_metrics(base_dir, "vol", "name", pv or args.pure_volume_name)
        vol_vm["volume"] = vol_vm.pop("name")
        sws = analyze_switch(base_dir, dur)
        heuristics = infer_heuristics(bio, io, tcp, host_vm, sws)

        # TEXT REPORT
        total = bio['all']['total_ios'] or 1
        r_pct = bio['reads']['total_ios'] / total * 100
        w_pct = bio['writes']['total_ios'] / total * 100
        avg_bs = bio['all']['total_bytes'] / total if total > 0 else 0
        
        print(f"\n===== SAN DEBUG ANALYZER REPORT v3.11 =====")
        print(f"Source      : {os.path.basename(args.path)}")
        print(f"Time Window : {format_ts(st)} -> {format_ts(et)} ({dur}s)")
        print(f"Device      : {io['device']}")
        print(f"Workload    : Read {r_pct:.1f}% / Write {w_pct:.1f}% | Avg Size: {int(avg_bs)} B ({avg_bs/1024:.1f} KiB)")
        print("-" * 50)

        # HOST I/O PRINT
        def print_bio_section(label, s):
            def pct(count): return (count / s["total_ios"] * 100.0) if s["total_ios"] else 0.0
            print(f"  ({label})")
            print(f"    Total IOs Traced : {s['total_ios']}")
            print(f"    Tail Distribution (Accumulated > X, plus <=1ms):")
            print(f"      <= 1 ms        : {s['count_lt_1ms']:<6} ({pct(s['count_lt_1ms']):.4f}%)")
            print(f"      >  1 ms        : {s['count_1ms']:<6} ({pct(s['count_1ms']):.4f}%)")
            print(f"      >  2 ms        : {s['count_2ms']:<6} ({pct(s['count_2ms']):.4f}%)")
            print(f"      >  3 ms        : {s['count_3ms']:<6} ({pct(s['count_3ms']):.4f}%)")
            print(f"      >  4 ms        : {s['count_4ms']:<6} ({pct(s['count_4ms']):.4f}%)")
            print(f"      >  5 ms        : {s['count_5ms']:<6} ({pct(s['count_5ms']):.4f}%)")
            print(f"      > 10 ms        : {s['count_10ms']:<6} ({pct(s['count_10ms']):.4f}%)")
            print(f"      > 20 ms        : {s['count_20ms']:<6} ({pct(s['count_20ms']):.4f}%)")
            print(f"      > 50 ms        : {s['count_50ms']:<6} ({pct(s['count_50ms']):.4f}%)")
            print(f"    Latency Percentiles (ms):")
            print(f"      Avg            : {s['avg']:.3f}")
            print(f"      P50            : {s['p50']:.3f}")
            print(f"      P90            : {s['p90']:.3f}")
            print(f"      P95            : {s['p95']:.3f}")
            print(f"      P99            : {s['p99']:.3f}")
            print(f"      P99.9          : {s['p999']:.3f}")
            print(f"      P99.99         : {s['p9999']:.3f} (Micro-stalls)")
            print(f"      Max            : {s['max_lat_ms']:.2f}")
            print(f"    IO Size per Latency Bucket (Avg):")
            for bkey in ["<=1", "1-2", "2-3", "3-4", "4-5", "5-10", "10-20", "20-50", ">50"]:
                b = s["buckets"][bkey]
                cnt = b["count"]
                avg = (b["bytes"] / cnt) if cnt > 0 else 0.0
                print(f"      {bkey:<6} : {cnt:7d} IOs, avg {int(avg)} B ({avg/1024:.1f} KiB)")

        print(f"\n[HOST I/O - BIOSNOOP]")
        print_bio_section("ALL OPS", bio["all"])
        print()
        print_bio_section("READS ONLY", bio["reads"])
        print()
        print_bio_section("WRITES ONLY", bio["writes"])

        print(f"\n[HOST AVG - IOSTAT]")
        val = io["avg_r_await_ms"]
        print(f"  r_await (read)   : {f'{val:.3f} ms' if val is not None else 'N/A'}")

        print(f"\n[NETWORK - PHYSICAL & SWITCH]")
        diff = find_file(base_dir, "ethtool_diff_errors", ".txt")
        if diff:
            clean = True
            for line in load_text_lines(diff):
                if "Clean" not in line and "---" not in line and line.strip():
                    print(f"  [HOST] {line.strip()}")
                    clean = False
            if clean: print("  [HOST] Clean (No CRC/Drops on host NIC)")
        else: print("  [HOST] N/A")

        if not sws: print("  [SWITCH] No switch metrics found")
        else:
            for s in sws:
                status = "Clean"
                details = []
                if s["drops_in"] > 0 or s["drops_out"] > 0 or s["errors"] > 0:
                    status = "ALERT"
                    details.append(f"DrIn={s['drops_in']:.0f} DrOut={s['drops_out']:.0f} Err={s['errors']:.0f}")
                if s["util_in_pct"] > 90 or s["util_out_pct"] > 90: status = "SATURATED"
                bw_str = f"RX={s['gbps_in']:.1f}G ({s['util_in_pct']:.0f}%) TX={s['gbps_out']:.1f}G ({s['util_out_pct']:.0f}%)"
                det_str = " ".join(details)
                print(f"  [SWITCH] {s['iface']:<8} -> {s['switch']}:{s['port']} [{status}]")
                print(f"           Speed: {s['speed']/1000:.1f}G | {bw_str} {det_str}")

        print(f"\n[NETWORK - TCP EXT]")
        print(f"  Out-of-Order     : {tcp.get('TCPOFOQueue', 0)}")
        print(f"  DSACK Recv       : {tcp.get('TCPDSACKRecvSegs', 0)}")
        print(f"  Retransmits      : {tcp.get('TCPRetransSegs', 0)}")

        def fmt_ms(v): return f"{v:.3f} ms" if v is not None else "N/A"
        def fmt_bytes(v): return f"{int(v)} B ({(v/1024):.1f} KiB)" if v is not None else "0 B"

        print(f"\n[STORAGE ARRAY - PURE (HOST)]")
        print(f"  Metric Host          : {host_vm['host']}")
        print(f"  SAN Latency (read)   : {fmt_ms(host_vm['san_read_ms'])} (Wire/Network)")
        print(f"  SAN Latency (write)  : {fmt_ms(host_vm['san_write_ms'])} (Wire/Network)")
        print(f"  Service Latency (R)  : {fmt_ms(host_vm['svc_read_ms'])} (Backend Processing)")
        print(f"  Service Latency (W)  : {fmt_ms(host_vm['svc_write_ms'])} (Backend Processing)")
        print(f"  Queue Latency (R)    : {fmt_ms(host_vm['queue_read_ms'])} (Internal Queue)")
        print(f"  Queue Latency (W)    : {fmt_ms(host_vm['queue_write_ms'])} (Internal Queue)")
        print(f"  IO Size (read)       : {fmt_bytes(host_vm['io_size_read'])}")
        print(f"  IO Size (write)      : {fmt_bytes(host_vm['io_size_write'])}")

        print(f"\n[STORAGE ARRAY - PURE (VOLUME)]")
        print(f"  Volume               : {vol_vm['volume']}")
        print(f"  SAN Latency (read)   : {fmt_ms(vol_vm['san_read_ms'])} (Wire/Network)")
        print(f"  SAN Latency (write)  : {fmt_ms(vol_vm['san_write_ms'])} (Wire/Network)")
        print(f"  Service Latency (R)  : {fmt_ms(vol_vm['svc_read_ms'])} (Backend Processing)")
        print(f"  Service Latency (W)  : {fmt_ms(vol_vm['svc_write_ms'])} (Backend Processing)")
        print(f"  Queue Latency (R)    : {fmt_ms(vol_vm['queue_read_ms'])} (Internal Queue)")
        print(f"  Queue Latency (W)    : {fmt_ms(vol_vm['queue_write_ms'])} (Internal Queue)")
        print(f"  IO Size (read)       : {fmt_bytes(vol_vm['io_size_read'])}")
        print(f"  IO Size (write)      : {fmt_bytes(vol_vm['io_size_write'])}")

        print("-" * 50)
        print(f"INTERPRETATION: {heuristics}")
        print("=" * 50 + "\n")
        
        if args.html:
            meta = {"source": os.path.basename(args.path), "device": io["device"], "time_window": f"{format_ts(st)} -> {format_ts(et)}", "duration": dur}
            # Set HTML filename based on ZIP filename
            zip_name = os.path.basename(args.path)
            html_name = os.path.splitext(zip_name)[0] + ".html"
            out = os.path.join(os.getcwd(), html_name)
            generate_html_report(out, bio, io, tcp, host_vm, vol_vm, sws, heuristics, meta)

    finally:
        if tmpdir and os.path.exists(tmpdir): shutil.rmtree(tmpdir)

if __name__ == "__main__":
    main()
