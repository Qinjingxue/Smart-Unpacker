import shutil
from typing import Callable, Optional

from sunpack.contracts.run_context import RunContext
from sunpack.postprocess.space_recovery import ArchiveSpaceRecovery


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
        self.space_recovery = ArchiveSpaceRecovery(context, postprocess_actions)
        self.disk_monitor: Optional[DiskSpaceGuard] = None

    def bind_root(self, root_path: str):
        self.disk_monitor = DiskSpaceGuard(root_path)

    def ensure_space(self, required_gb: int) -> bool:
        if not self.disk_monitor:
            return True
        with self.context.lock:
            return self.disk_monitor.ensure_space(required_gb, self.space_recovery.cleanup_next_archive_group)
