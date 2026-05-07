from sunpack_native import zip_directory_field_repair
import json

# Find an encrypted ZIP
import os
root = r'C:\Users\29402\Desktop\sunpack\repair_training\material\zip'
for dd in os.listdir(root):
    d = os.path.join(root, dd)
    if not os.path.isdir(d): continue
    for f in os.listdir(d):
        if 'encrypted' in f and f.endswith('.zip'):
            path = os.path.join(d, f)
            size = os.path.getsize(path)
            print(f'Found: {f} ({size} bytes)')
            src = {"kind": "file", "path": path, "entry_path": path, "format_hint": "zip", "password": "sunpack"}
            result = dict(zip_directory_field_repair(src, r'C:\temp', 'zip_trailing_junk_trim', 512.0))
            print(f'Result status: {result.get("status")}')
            print(f'Message: {str(result.get("message",""))[:200]}')
            import sys; sys.exit(0)
print('No encrypted ZIP found')
