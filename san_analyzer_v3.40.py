#!/usr/bin/env python3
import sys
import numpy as np

def format_size(bytes_val):
    return f"{bytes_val:.0f} B ({bytes_val/1024:.1f} KiB)"

def print_report_section(data, label):
    if len(data) == 0: 
        print(f"\n [{label}] - Sem dados suficientes.")
        return
    
    lats_ms = data[:, 2] / 1000.0
    sizes = data[:, 1]
    total = len(lats_ms)
    
    print(f"\n [{label}]")
    print(f"    Total IOs Traced : {total}")
    print(f"    Tail Distribution (Accumulated > X, plus <=1ms):")
    
    le1 = np.sum(lats_ms <= 1)
    print(f"      <= 1 ms        : {le1:8} ({le1/total*100:8.4f}%)")
    for b in [1, 2, 3, 4, 5, 10, 20, 50]:
        count = np.sum(lats_ms > b)
        print(f"      > {b:2} ms        : {count:8} ({count/total*100:8.4f}%)")
        
    print(f"    Latency Percentiles (ms):")
    print(f"      Avg            : {np.mean(lats_ms):.3f}")
    for p in [50, 90, 95, 99, 99.9, 99.99]:
        note = " (Micro-stalls)" if p == 99.99 else ""
        print(f"      P{p:<13} : {np.percentile(lats_ms, p):.3f}{note}")
    print(f"      Max            : {np.max(lats_ms):.2f}")

    print(f"    IO Size per Latency Bucket (Avg):")
    mask_le1 = lats_ms <= 1
    if np.any(mask_le1):
        print(f"      <=1    : {np.sum(mask_le1):8} IOs, avg {format_size(np.mean(sizes[mask_le1]))}")
    
    bounds = [1, 2, 3, 4, 5, 10, 20, 50]
    for i in range(len(bounds)-1):
        low, high = bounds[i], bounds[i+1]
        mask = (lats_ms > low) & (lats_ms <= high)
        if np.any(mask):
            print(f"      {low}-{high:<4} : {np.sum(mask):8} IOs, avg {format_size(np.mean(sizes[mask]))}")
            
    mask_gt50 = lats_ms > 50
    if np.any(mask_gt50):
        print(f"      >50    : {np.sum(mask_gt50):8} IOs, avg {format_size(np.mean(sizes[mask_gt50]))}")

def main(filename):
    print(f"Analyzing {filename}...")
    raw_list = []
    
    # Leitura com filtro anti-lixo (ignora cabecalhos do bpftrace)
    with open(filename, 'r') as f:
        for line in f:
            p = line.split()
            # Verifica se tem 3 colunas E se a primeira é 'R' ou 'W'
            if len(p) == 3 and p[0] in ('R', 'W'):
                try:
                    # Converte para [Tipo, Tamanho, Latencia_us]
                    raw_list.append([1 if p[0]=='R' else 0, int(p[1]), int(p[2])])
                except ValueError:
                    # Se falhar na conversao do numero, ignora a linha
                    pass
    
    if not raw_list:
        print("Erro: Nenhum dado de I/O valido encontrado no log.")
        sys.exit(1)
        
    all_data = np.array(raw_list)
    reads = all_data[all_data[:, 0] == 1]
    writes = all_data[all_data[:, 0] == 0]
    
    print("\n" + "="*40)
    print("===== SAN DEBUG ANALYZER REPORT v3.41 =====")
    print(f"Workload    : Read {len(reads)/len(all_data)*100:.1f}% / Write {len(writes)/len(all_data)*100:.1f}%")
    print(f"Avg Size    : {format_size(np.mean(all_data[:,1]))}")
    print("="*40)
    
    print_report_section(all_data, "ALL OPS")
    print_report_section(reads, "READS ONLY")
    print_report_section(writes, "WRITES ONLY")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 analyzer_ebpf.py <arquivo_raw.log>")
        sys.exit(1)
    main(sys.argv[1])
