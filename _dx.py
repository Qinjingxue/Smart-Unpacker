import json, collections, os
os.chdir(r'C:\Users\29402\Desktop\sunpack\repair_training\datasets')

from collections import defaultdict
episodes = defaultdict(list)

for fname in ['repair_plan_ltr_success_zip_v12.jsonl', 'repair_plan_ltr_failure_zip_v12.jsonl']:
    with open(fname, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip(): continue
            d = json.loads(line)
            if d.get('row_type') == 'terminal': continue
            if not d.get('action_row_id'): continue
            eid = d.get('episode_id', d.get('sample_id', '?'))
            episodes[eid].append(d)

variant_outcomes = defaultdict(lambda: collections.Counter())
for eid, rows in episodes.items():
    best_l = max(int(r.get('label', 0) or 0) for r in rows)
    r = rows[0]
    src = r.get('source_derivation', {})
    variant = src.get('zip_variant', '?')
    variant_outcomes[variant][str(best_l)] += 1

print('V12 ENCRYPTED ZIP FOCUS:')
for variant in ['encrypted_zipcrypto', 'sfx_stub', 'sfx_split_zip']:
    oc = variant_outcomes.get(variant, {})
    t = sum(oc.values())
    term = oc.get('3', 0)
    rep = oc.get('2', 0)
    part = oc.get('1', 0)
    noout = oc.get('0', 0)
    pct = 100*(term+rep)/max(1,t)
    print(f'{variant}: total={t} term={term} rep={rep} part={part} noout={noout} FIX={pct:.0f}%')

all_labels = collections.Counter()
for eid, rows in episodes.items():
    all_labels[str(max(int(r.get('label',0) or 0) for r in rows))] += 1
print(f'\nOverall: {dict(all_labels.most_common())}')
print(f'Terminal: {all_labels.get("3",0)}, Fixable: {all_labels.get("2",0)+all_labels.get("3",0)}')
print(f'Total episodes: {len(episodes)}')
