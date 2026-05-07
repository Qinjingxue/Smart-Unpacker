import json, collections
modules = collections.Counter()
for fname in ['repair_training/datasets/repair_plan_ltr_success.jsonl']:
    with open(fname,'r',encoding='utf-8') as f:
        for line in f:
            if not line.strip(): continue
            d = json.loads(line)
            if d.get('row_type') == 'terminal': continue
            if d.get('action_row_id'):
                modules[str(d.get('module','?'))] += 1
print('Modules:', dict(modules.most_common()))
