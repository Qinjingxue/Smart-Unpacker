from __future__ import annotations

import os
import subprocess


class Extractor:
    def __init__(self, engine):
        self.engine = engine

    def has_definite_wrong_password(self, err_text):
        err_lower = (err_text or "").lower()
        return (
            "cannot open encrypted archive. wrong password?" in err_lower
            or "error: wrong password :" in err_lower
        )

    def has_archive_damage_signals(self, err_text):
        err_lower = (err_text or "").lower()
        return any(
            marker in err_lower
            for marker in (
                "unexpected end of archive",
                "missing volume",
                "crc failed",
                "data error in encrypted file",
                "headers error",
                "can not open the file as archive",
                "cannot open the file as",
            )
        )

    def find_working_password(self, archive, startupinfo):
        last_error = ""
        last_result = None
        passwords_to_try = list(self.engine.passwords) if self.engine.passwords else [""]
        for pwd in passwords_to_try:
            cmd = [self.engine.seven_z_path, "t", archive, "-y"]
            if pwd:
                cmd.append(f"-p{pwd}")
            result = subprocess.run(cmd, capture_output=True, text=True, startupinfo=startupinfo, stdin=subprocess.DEVNULL)
            combined = f"{result.stdout}\n{result.stderr}"
            if result.returncode == 0:
                self.engine.add_recent_password(pwd)
                return pwd, result, ""
            last_result = result
            last_error = combined.lower()
            if self.has_archive_damage_signals(last_error) and not self.has_definite_wrong_password(last_error):
                return pwd, result, last_error
            if "wrong password" not in last_error:
                return None, result, last_error
        return None, last_result, last_error

    def extract_archive_once(self, archive, out_dir, password, startupinfo):
        cmd = [self.engine.seven_z_path, "x", archive, f"-o{out_dir}", "-y"]
        if password is not None:
            cmd.append(f"-p{password}")
        return subprocess.run(cmd, capture_output=True, text=True, startupinfo=startupinfo, stdin=subprocess.DEVNULL)

    def classify_extract_error(self, run_result, err_text, archive=None, all_parts=None):
        error_msg = "原因未知"
        archive_name = os.path.basename(archive or "").lower()
        is_split_archive = bool(all_parts and len(all_parts) > 1) or self.engine.relation_builder.detect_filename_split_role(archive_name) is not None
        err_lower = (err_text or "").lower()

        if "missing volume" in err_lower:
            return "分卷缺失或不完整"
        if "unexpected end of archive" in err_lower:
            return "分卷缺失或不完整" if is_split_archive else "压缩包损坏"
        if "crc failed" in err_lower or "data error in encrypted file" in err_lower:
            if self.has_definite_wrong_password(err_lower):
                return "密码错误"
            return "压缩包损坏"
        if "headers error" in err_lower or "data error" in err_lower:
            return "压缩包损坏"
        if "cannot open the file as" in err_lower or "can not open the file as archive" in err_lower:
            return "分卷缺失或不完整" if is_split_archive else "压缩包损坏"
        if "wrong password" in err_lower:
            return "密码错误"

        if run_result:
            code = run_result.returncode
            if code == 1:
                error_msg = "警告 (文件被占用或部分失败)"
            elif code == 2:
                error_msg = "致命错误 (文件损坏或格式不支持)"
            elif code == 7:
                error_msg = "命令行参数错误"
            elif code == 8:
                error_msg = "内存/磁盘空间不足"
            elif code == 255:
                error_msg = "用户中断"
        return error_msg

    def extract(self, task):
        key = task.key
        archive = task.main_path
        all_parts = task.all_parts
        main_info = task.group_info.main_info
        retry_count = 0
        with self.engine.concurrency_cond:
            while self.engine.active_workers >= self.engine.current_concurrency_limit:
                self.engine.concurrency_cond.wait()
            self.engine.active_workers += 1
        try:
            with self.engine.lock:
                self.engine.in_progress.add(key)
            out_dir = os.path.join(os.path.dirname(archive), os.path.basename(key))
            if out_dir.lower() == archive.lower():
                out_dir += "_extracted"

            while retry_count < self.engine.max_retries:
                if not self.engine.cleanup_manager.ensure_space(5):
                    return None
                self.engine.log(f"\n[EXTRACT] 开始: {archive}")

                try:
                    os.makedirs(out_dir, exist_ok=True)
                except Exception as e:
                    self.engine.log(f"[ERROR] 无法创建输出目录 {out_dir}: {e}")
                    self.engine.failed_tasks.append(f"{os.path.basename(archive)} [目录创建失败]")
                    return None

                startupinfo = self.engine._make_startupinfo()
                extract_result = None
                test_result = None
                err = ""

                if self.engine.passwords:
                    if main_info.validation_ok and not main_info.validation_encrypted:
                        correct_pwd = ""
                    else:
                        correct_pwd, test_result, err = self.engine._find_working_password(archive, startupinfo)
                else:
                    correct_pwd = ""

                if not self.engine.passwords:
                    extract_result = self.extract_archive_once(archive, out_dir, correct_pwd, startupinfo)
                    if extract_result.returncode == 0:
                        self.engine.log(f"[EXTRACT] 成功: {archive}")
                        with self.engine.lock:
                            self.engine.unpacked_archives.append(all_parts)
                            self.engine.processed.add(key)
                        return out_dir
                    err = f"{extract_result.stdout}\n{extract_result.stderr}".lower()
                elif correct_pwd is not None:
                    extract_result = self.extract_archive_once(archive, out_dir, correct_pwd, startupinfo)
                    if extract_result.returncode == 0:
                        self.engine.log(f"[EXTRACT] 成功: {archive}")
                        with self.engine.lock:
                            self.engine.unpacked_archives.append(all_parts)
                            self.engine.processed.add(key)
                        return out_dir
                    err = f"{extract_result.stdout}\n{extract_result.stderr}".lower()
                elif test_result:
                    err = f"{test_result.stdout}\n{test_result.stderr}".lower()

                if extract_result and ("no space" in err or "write error" in err or extract_result.returncode == 8):
                    if self.engine.cleanup_manager.ensure_space(10):
                        retry_count += 1
                        continue

                error_msg = self.classify_extract_error(extract_result or test_result, err, archive=archive, all_parts=all_parts)
                self.engine.cleanup_manager.cleanup_failed_output(out_dir)
                self.engine.failed_tasks.append(f"{os.path.basename(archive)} [{error_msg}]")
                self.engine.log(f"[EXTRACT] 失败: {archive} (错误: {error_msg})")
                return None
        finally:
            with self.engine.lock:
                self.engine.in_progress.discard(key)
            with self.engine.concurrency_cond:
                self.engine.active_workers -= 1
                self.engine.concurrency_cond.notify_all()
