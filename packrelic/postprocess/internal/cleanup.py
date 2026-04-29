import os
from typing import Iterable

from send2trash import send2trash
from packrelic_native import delete_files_batch as _native_delete_files_batch


class ArchiveCleanup:
    def __init__(self, mode: str = "recycle", language: str = "en"):
        self.mode = mode
        self.language = "zh" if str(language or "").strip().lower() == "zh" else "en"

    def text(self, en: str, zh: str) -> str:
        return zh if self.language == "zh" else en

    def cleanup_success_archives(self, archives_to_clean: Iterable[Iterable[str]]):
        archives = [list(parts) for parts in archives_to_clean]
        if self.mode == "keep":
            print(self.text(
                "\n[CLEAN] Task finished, config is set to keep successfully extracted archives.",
                "\n[CLEAN] 任务完成，配置为保留成功解压的原压缩包。",
            ))
        else:
            print(self.text(
                "\n[CLEAN] Task finished, starting cleanup of successfully extracted archives...",
                "\n[CLEAN] 任务完成，开始清理成功解压的原压缩包...",
            ))

        if not archives:
            print(self.text("[CLEAN] No archives found that require cleanup.", "[CLEAN] 没有需要清理的压缩包。"))
            return

        if self.mode == "delete":
            self._delete_archive_files([path for parts in archives for path in parts])
            return

        for parts in archives:
            for path in parts:
                self.cleanup_archive_file(path)

    def cleanup_archive_file(self, path: str, reason: str = "[CLEAN]"):
        archive_path = os.path.normpath(path)
        if not os.path.exists(archive_path):
            print(self.text(
                f"[DEBUG] File not found, skipping cleanup: {archive_path}",
                f"[DEBUG] 文件不存在，跳过清理：{archive_path}",
            ))
            return

        filename = os.path.basename(archive_path)
        if self.mode == "keep":
            print(self.text(f"{reason} Keeping original archive: {filename}", f"{reason} 保留原压缩包：{filename}"))
            return

        if self.mode == "delete":
            self._delete_archive_files([archive_path], reason=reason)
            return

        print(self.text(f"{reason} Moving to recycle bin: {filename}", f"{reason} 移动到回收站：{filename}"))
        try:
            send2trash(archive_path)
        except Exception as exc:
            print(self.text(
                f"[ERROR] Failed to move to recycle bin: {filename} ({exc})",
                f"[ERROR] 移动到回收站失败：{filename} ({exc})",
            ))

    def _delete_archive_files(self, paths: list[str], reason: str = "[CLEAN]"):
        existing = []
        for path in paths:
            archive_path = os.path.normpath(path)
            filename = os.path.basename(archive_path)
            if not os.path.exists(archive_path):
                print(self.text(
                    f"[DEBUG] File not found, skipping cleanup: {archive_path}",
                    f"[DEBUG] 文件不存在，跳过清理：{archive_path}",
                ))
                continue
            print(self.text(f"{reason} Completely deleting: {filename}", f"{reason} 彻底删除：{filename}"))
            existing.append(archive_path)
        for item in _native_delete_files_batch(existing):
            if str(item.get("status") or "") != "error":
                continue
            filename = str(item.get("filename") or os.path.basename(str(item.get("path") or "")))
            error = str(item.get("error") or "")
            print(self.text(
                f"[ERROR] Failed to completely delete: {filename} ({error})",
                f"[ERROR] 彻底删除失败：{filename} ({error})",
            ))
