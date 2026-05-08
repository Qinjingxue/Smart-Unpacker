import json, collections, os
os.chdir(r'C:\Users\29402\Desktop\sunpack\repair_training\datasets')
from collections import defaultdict

for ver in ['v12', 'v15']:
    episodes = defaultdict(list)
    for fname in [f'repair_plan_ltr_success_zip_{ver}.jsonl', f'repair_plan_ltr_failure_zip_{ver}.jsonl']:
        with open(fname, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                d = json.loads(line)
                if d.get('row_type') == 'terminal': continue
                if not d.get('action_row_id'): continue
                episodes[d.get('episode_id', '?')].append(d)
    
    var_oc = defaultdict(lambda: collections.Counter())
    for eid, rows in episodes.items():
        best_l = max(int(r.get('label',0) or 0) for r in rows)
        src = rows[0].get('source_derivation',{})
        var = src.get('zip_variant','?')
        var_oc[var][str(best_l)] += 1
    
    all_labels = collections.Counter()
    for eid, rows in episodes.items():
        all_labels[str(max(int(r.get('label',0) or 0) for r in rows))] += 1
    
    print(f'=== {ver.upper()} ===')
    print(f'  episodes: {len(episodes)}')
    print(f'  overall: {dict(all_labels.most_common())}')
    print(f'  terminal: {all_labels.get("3",0)}, fixable(>=2): {all_labels.get("2",0)+all_labels.get("3",0)}')
    for var in ['encrypted_zipcrypto', 'sfx_stub', 'split_zip', 'sfx_split_zip']:
        oc = var_oc.get(var,{})
        t = sum(oc.values())
        print(f'  {var}: total={t} T={oc.get("3",0)} R={oc.get("2",0)} P={oc.get("1",0)} N={oc.get("0",0)}')
    print()
