from __future__ import annotations

import os
import shutil
import time

from send2trash import send2trash


class CleanupManager:
    def __init__(self, engine):
        self.engine = engine

    def ensure_space(self, required_gb=5):
        required_bytes = required_gb * 1024 ** 3
        while True:
            try:
                if shutil.disk_usage(self.engine.root_dir).free > required_bytes:
                    break
            except Exception:
                return False
            with self.engine.lock:
                if not self.engine.unpacked_archives:
                    self.engine.log("[CRITICAL] 磁盘已满，无可删除的压缩包！")
                    return False
                for f in self.engine.unpacked_archives.popleft():
                    if os.path.exists(f):
                        self.engine.log(f"[SPACE] 释放空间：正在删除 {os.path.basename(f)}")
                        try:
                            send2trash(f)
                        except Exception:
                            try:
                                os.remove(f)
                            except Exception:
                                pass
        return True

    def cleanup_failed_output(self, out_dir):
        if os.path.exists(out_dir):
            try:
                shutil.rmtree(out_dir)
            except Exception:
                pass

    def cleanup_success_archives(self):
        self.engine.log("\n[CLEAN] 任务结束，开始清理已成功解压的归档文件...")
        with self.engine.lock:
            if not self.engine.unpacked_archives:
                self.engine.log("[CLEAN] 没有发现需要清理的归档文件。")
            while self.engine.unpacked_archives:
                parts = self.engine.unpacked_archives.popleft()
                for f in parts:
                    f = os.path.normpath(f)
                    if os.path.exists(f):
                        fname = os.path.basename(f)
                        self.engine.log(f"[CLEAN] 正在清理: {fname}")
                        try:
                            send2trash(f)
                        except Exception as e:
                            self.engine.log(f"[WARN] 无法移至回收站 ({e})，尝试直接删除: {fname}")
                            try:
                                os.remove(f)
                            except Exception as e2:
                                self.engine.log(f"[ERROR] 彻底删除失败: {fname} (错误: {e2})")
                    else:
                        self.engine.log(f"[DEBUG] 文件已不存在，跳过清理: {f}")

    def log_final_summary(self, start_time, success_count):
        self.engine.log("\n" + "=" * 20 + " 处理结果汇总 " + "=" * 20)
        self.engine.log(f"总计耗时: {(time.time() - start_time) / 60:.2f} 分钟")
        self.engine.log(f"成功解压: {success_count} 个")
        if self.engine.failed_tasks:
            self.engine.log(f"失败任务: {len(self.engine.failed_tasks)} 个")
            log_path = os.path.join(self.engine.root_dir, "failed_log.txt")
            try:
                with open(log_path, "w", encoding="utf-8") as f_log:
                    for ft in self.engine.failed_tasks:
                        self.engine.log(f" [×] {ft}")
                        f_log.write(f"{ft}\n")
                self.engine.log(f"详细失败列表已保存至: {log_path}")
            except Exception:
                self.engine.log("[ERROR] 无法保存失败日志文件。")
        else:
            self.engine.log(" [√] 全部任务已成功处理！")
        self.engine.log("=" * 54)

    def flatten_dirs(self, base):
        self.engine.log("\n[CLEAN] 压平单分支目录...")
        for root, dirs, files in os.walk(base, topdown=False):
            if len(dirs) == 1 and not files:
                child_path = os.path.join(root, dirs[0])
                if os.path.exists(child_path):
                    for item in os.listdir(child_path):
                        src, dst = os.path.join(child_path, item), os.path.join(root, item)
                        final_dst = dst
                        if os.path.exists(dst) and os.path.abspath(src).lower() != os.path.abspath(dst).lower():
                            b, e = os.path.splitext(item)
                            c = 1
                            while os.path.exists(final_dst):
                                final_dst = os.path.join(root, f"{b} ({c}){e}")
                                c += 1
                        try:
                            shutil.move(src, final_dst)
                        except Exception:
                            pass
                    try:
                        os.rmdir(child_path)
                    except Exception:
                        pass
