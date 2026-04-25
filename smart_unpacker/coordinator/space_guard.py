import shutil
from typing import Callable, Optional

from smart_unpacker.coordinator.context import RunContext


class DiskSpaceGuard:
    def __init__(self, root_dir: str):
        self.root_dir = root_dir

    def ensure_space(
        self,
        required_gb: int,
        cleanup_next: Callable[[], bool],
    ) -> bool:
        required_bytes = required_gb * 1024 ** 3

        while True:
            try:
                if shutil.disk_usage(self.root_dir).free > required_bytes:
                    break
            except Exception:
                return False

            if not cleanup_next():
                return False

        return True


class ExtractionSpaceGuard:
    def __init__(self, context: RunContext, postprocess_actions):
        self.context = context
        self.postprocess_actions = postprocess_actions
        self.disk_monitor: Optional[DiskSpaceGuard] = None

    def bind_root(self, root_path: str):
        self.disk_monitor = DiskSpaceGuard(root_path)

    def ensure_space(self, required_gb: int) -> bool:
        if not self.disk_monitor:
            return True
        with self.context.lock:
            return self.disk_monitor.ensure_space(required_gb, self._cleanup_next_archive_group)

    def _cleanup_next_archive_group(self) -> bool:
        if self.postprocess_actions.cleanup_mode == "keep":
            print("[CRITICAL] Disk is full, but config is set to keep original archives. Cannot free space.")
            return False

        if not self.context.unpacked_archives:
            print("[CRITICAL] Disk is full, no archives left to delete!")
            return False

        parts_to_delete = self.context.unpacked_archives.pop(0)
        for path in parts_to_delete:
            self.postprocess_actions.cleanup_archive_file(path, "[SPACE] Freeing space: ")
        return True
