import json
with open('repair_training/datasets/repair_plan_ltr_success_zip_v12.jsonl','r',encoding='utf-8') as f:
    for line in f:
        if not line.strip(): continue
        d = json.loads(line)
        if d.get('row_type') == 'terminal': continue
        if not d.get('action_row_id'): continue
        src = d.get('source_derivation',{})
        if src.get('zip_variant','') == 'sfx_stub':
            print('source_derivation keys:', list(src.keys())[:10])
            print('zip_variant:', src.get('zip_variant'))
            print('zip_container_tags:', src.get('zip_container_tags'))
            # Check the state's damage_flags vs candidate's
            sf = d.get('state_features',{})
            print('state damage_flags:', sf.get('damage_flags',[])[:10])
            cand = d.get('stable_features',{}).get('candidate',{})
            print('candidate damage_flags:', cand.get('damage_flags',[])[:10])
            break
