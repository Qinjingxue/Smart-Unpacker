import json
f = open('repair_training/datasets/.collect_shards/task_failure_00000.jsonl', 'r', encoding='utf-8')
d = json.loads(f.readline())
print('message:', d.get('message','')[:500])
print('error:', d.get('error','')[:500])
print('all keys:', list(d.keys()))
f.close()
