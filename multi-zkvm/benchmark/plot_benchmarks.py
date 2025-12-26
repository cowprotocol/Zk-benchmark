#!/usr/bin/env python3
import json
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

with open('benchmark_results.json', 'r') as f:
    data = json.load(f)

results = data['results']

latest_results = {}
for result in results:
    key = (result['zkvm'], result['num_signers'])
    if key not in latest_results or result['timestamp'] > latest_results[key]['timestamp']:
        latest_results[key] = result

grouped = defaultdict(lambda: defaultdict(dict))
for result in latest_results.values():
    num_signers = result['num_signers']
    zkvm = result['zkvm']
    grouped[num_signers][zkvm] = result

signer_counts = sorted(grouped.keys())
zkvms = sorted(set(r['zkvm'] for r in latest_results.values()))

print(f"Found data for signer counts: {signer_counts}")
print(f"Found zkVMs: {zkvms}")

cycles_data = {zkvm: [] for zkvm in zkvms}
exec_time_data = {zkvm: [] for zkvm in zkvms}
prove_time_data = {zkvm: [] for zkvm in zkvms}

for num_signers in signer_counts:
    for zkvm in zkvms:
        if zkvm in grouped[num_signers]:
            r = grouped[num_signers][zkvm]
            cycles_data[zkvm].append(r['execution_cycles'] / 1_000_000)  
            exec_time_data[zkvm].append(r['execution_duration'])
            prove_time_data[zkvm].append(r['proving_duration'])
        else:
            cycles_data[zkvm].append(0)
            exec_time_data[zkvm].append(0)
            prove_time_data[zkvm].append(0)

colors = {
    'sp1': '#FF69B4',      
    'risc0': '#FFD700',    
    'zisk': '#32CD32',     
    'pico': '#808080'      
}

proof_types = {
    'sp1': 'Groth16',
    'risc0': 'Groth16',
    'zisk': 'Compressed',
    'pico': 'Compressed'
}

fig, axes = plt.subplots(1, 3, figsize=(18, 6))
fig.suptitle('zkVM Benchmarks', fontsize=18, fontweight='bold')

x = np.arange(len(signer_counts))
width = 0.2
offsets = {zkvm: i * width for i, zkvm in enumerate(zkvms)}

ax1 = axes[0]
for zkvm in zkvms:
    bars = ax1.bar(x + offsets[zkvm], cycles_data[zkvm], width, 
                   label=zkvm.upper(), color=colors.get(zkvm, 'gray'))
    
    for i, bar in enumerate(bars):
        height = bar.get_height()
        if height > 0:
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f}M',
                    ha='center', va='bottom', fontsize=9)

ax1.set_xlabel('Number of Signers', fontsize=12, fontweight='bold')
ax1.set_ylabel('Execution Cycles (Millions)', fontsize=12, fontweight='bold')
ax1.set_title('Execution Cycles', fontsize=13, fontweight='bold')
ax1.set_xticks(x + width * (len(zkvms) - 1) / 2)
ax1.set_xticklabels(signer_counts)
ax1.legend()
ax1.grid(True, alpha=0.3, axis='y')

ax1.set_ylim(bottom=0, top=max([max(v) for v in cycles_data.values()]) * 1.15)

ax2 = axes[1]
for zkvm in zkvms:
    bars = ax2.bar(x + offsets[zkvm], exec_time_data[zkvm], width,
                   label=zkvm.upper(), color=colors.get(zkvm, 'gray'))
    
    for i, bar in enumerate(bars):
        height = bar.get_height()
        if height > 0:
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f}s',
                    ha='center', va='bottom', fontsize=9)

ax2.set_xlabel('Number of Signers', fontsize=12, fontweight='bold')
ax2.set_ylabel('Time (s)', fontsize=12, fontweight='bold')
ax2.set_title('Execution Time', fontsize=13, fontweight='bold')
ax2.set_xticks(x + width * (len(zkvms) - 1) / 2)
ax2.set_xticklabels(signer_counts)
ax2.legend()
ax2.grid(True, alpha=0.3, axis='y')
ax2.set_yscale('log')  

ax3 = axes[2]
for zkvm in zkvms:
    bars = ax3.bar(x + offsets[zkvm], prove_time_data[zkvm], width,
                   label=zkvm.upper(), color=colors.get(zkvm, 'gray'))
    
    for i, bar in enumerate(bars):
        height = bar.get_height()
        if height > 0:
            ax3.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f}s',
                    ha='center', va='bottom', fontsize=9)

ax3.set_xlabel('Number of Signers', fontsize=12, fontweight='bold')
ax3.set_ylabel('Time (s)', fontsize=12, fontweight='bold')
ax3.set_title('Proof Generation Time', fontsize=13, fontweight='bold')
ax3.set_xticks(x + width * (len(zkvms) - 1) / 2)
ax3.set_xticklabels(signer_counts)
ax3.legend()
ax3.grid(True, alpha=0.3, axis='y')
ax3.set_ylim(bottom=0, top=max([max(v) for v in prove_time_data.values()]) * 1.15)

plt.tight_layout()
plt.savefig('benchmark_comparison.png', dpi=300, bbox_inches='tight')
print("\n✓ Generated benchmark_comparison.png")

print("\n" + "="*90)
print("BENCHMARK SUMMARY")
print("="*90)
for num_signers in signer_counts:
    print(f"\n{num_signers} Signers:")
    print(f"  {'zkVM':<10} {'Proof Type':<12} {'Cycles (M)':<15} {'Exec Time (s)':<18} {'Prove Time (s)':<18}")
    print(f"  {'-'*10} {'-'*12} {'-'*15} {'-'*18} {'-'*18}")
    for zkvm in zkvms:
        if zkvm in grouped[num_signers]:
            r = grouped[num_signers][zkvm]
            cycles_m = r['execution_cycles'] / 1_000_000
            proof_type = proof_types.get(zkvm, 'Unknown')
            print(f"  {zkvm.upper():<10} {proof_type:<12} {cycles_m:<15.2f} "
                  f"{r['execution_duration']:<18.3f} {r['proving_duration']:<18.3f}")