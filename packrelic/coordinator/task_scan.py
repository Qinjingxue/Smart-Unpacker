from typing import Any

from packrelic.contracts.run_context import RunContext
from packrelic.contracts.tasks import ArchiveTask
from packrelic.detection import ArchiveTaskProvider


class ArchiveTaskScanner:
    def __init__(self, config: dict[str, Any], context: RunContext):
        self.context = context
        self.provider = ArchiveTaskProvider(config)
        self.detector = self.provider.detector

    def scan_root(self, scan_root: str) -> list[ArchiveTask]:
        return self.scan_targets([scan_root])

    def scan_targets(self, scan_roots: list[str]) -> list[ArchiveTask]:
        tasks = self.provider.scan_targets(scan_roots, processed_keys=self.context.processed_keys)
        for failure in self.provider.failed_candidates:
            if failure not in self.context.failed_tasks:
                self.context.failed_tasks.append(failure)
        return tasks
