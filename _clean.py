import shutil, os
root = r'C:\Users\29402\Desktop\sunpack\repair_training\material\zip'
for dd in os.listdir(root):
    d = os.path.join(root, dd)
    if not os.path.isdir(d): continue
    shutil.rmtree(os.path.join(d, 'damaged'), ignore_errors=True)
    for f in list(os.listdir(d)):
        fp = os.path.join(d, f)
        if f.endswith(('.zip', '.derived.json', '.split.json')) or f.startswith('damage_manifest'):
            try: os.remove(fp)
            except OSError: pass
        if f.endswith('.volumes'):
            try: shutil.rmtree(fp, ignore_errors=True)
            except OSError: pass
    print('cleaned:', dd)
print('done')
