import json
path = 'repair_training/datasets/repair_plan_ltr_failure.jsonl'
f = open(path, 'r', encoding='utf-8')
d = json.loads(f.readline())
for k, v in sorted(d.items()):
    print(k, '=', str(v)[:120])
f.close()
