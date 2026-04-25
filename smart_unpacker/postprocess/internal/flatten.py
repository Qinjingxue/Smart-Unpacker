import os
import shutil


class DirectoryFlattener:
    def flatten_dirs(self, base: str):
        print("\n[CLEAN] Flattening single-branch directories...")
        for root, dirs, files in os.walk(base, topdown=False):
            if len(dirs) == 1 and not files:
                child_path = os.path.join(root, dirs[0])
                if os.path.exists(child_path):
                    for item in os.listdir(child_path):
                        src = os.path.join(child_path, item)
                        dst = os.path.join(root, item)
                        final_dst = dst

                        if os.path.exists(dst) and os.path.abspath(src).lower() != os.path.abspath(dst).lower():
                            base_name, ext = os.path.splitext(item)
                            count = 1
                            while os.path.exists(final_dst):
                                final_dst = os.path.join(root, f"{base_name} ({count}){ext}")
                                count += 1
                        try:
                            shutil.move(src, final_dst)
                        except Exception:
                            pass

                    try:
                        os.rmdir(child_path)
                    except Exception:
                        pass
