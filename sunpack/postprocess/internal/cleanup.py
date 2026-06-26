import os
from typing import Iterable

from send2trash import send2trash
from sunpack_native import delete_files_batch as _native_delete_files_batch
from sunpack.i18n import I18nContext


class ArchiveCleanup:
    def __init__(self, mode: str = "recycle", language: str = "en"):
        self.mode = mode
        self.i18n = I18nContext(language)

    def cleanup_success_archives(self, archives_to_clean: Iterable[Iterable[str]]):
        archives = [list(parts) for parts in archives_to_clean]
        if self.mode == "keep":
            print(self.i18n.t("cleanup.keep_done"))
        else:
            print(self.i18n.t("cleanup.start"))

        if not archives:
            print(self.i18n.t("cleanup.none"))
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
            print(self.i18n.t("cleanup.file_missing", path=archive_path))
            return

        filename = os.path.basename(archive_path)
        if self.mode == "keep":
            print(self.i18n.t("cleanup.keep_file", reason=reason, filename=filename))
            return

        if self.mode == "delete":
            self._delete_archive_files([archive_path], reason=reason)
            return

        print(self.i18n.t("cleanup.recycle", reason=reason, filename=filename))
        try:
            send2trash(archive_path)
        except Exception as exc:
            print(self.i18n.t("cleanup.recycle_failed", filename=filename, error=exc))

    def _delete_archive_files(self, paths: list[str], reason: str = "[CLEAN]"):
        existing = []
        for path in paths:
            archive_path = os.path.normpath(path)
            filename = os.path.basename(archive_path)
            if not os.path.exists(archive_path):
                print(self.i18n.t("cleanup.file_missing", path=archive_path))
                continue
            print(self.i18n.t("cleanup.delete", reason=reason, filename=filename))
            existing.append(archive_path)
        for item in _native_delete_files_batch(existing):
            if str(item.get("status") or "") != "error":
                continue
            filename = str(item.get("filename") or os.path.basename(str(item.get("path") or "")))
            error = str(item.get("error") or "")
            print(self.i18n.t("cleanup.delete_failed", filename=filename, error=error))
