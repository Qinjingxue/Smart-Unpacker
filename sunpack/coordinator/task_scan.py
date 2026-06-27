import os
from types import SimpleNamespace
from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.run_context import RunContext
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.coordinator.analysis_stage import ArchiveAnalysisStage


class ArchiveTaskScanner:
    def __init__(self, config: dict[str, Any], context: RunContext, analysis_stage: ArchiveAnalysisStage | None = None):
        self.context = context
        self.provider = ArchiveTaskProvider(config, analysis_stage=analysis_stage)
        self.detector = self.provider.detector

    def scan_root(self, scan_root: str) -> list[ArchiveTask]:
        return self.scan_targets([scan_root])

    def scan_targets(self, scan_roots: list[str]) -> list[ArchiveTask]:
        tasks = self.provider.scan_targets(scan_roots, processed_keys=self.context.processed_keys)
        for failure in self.provider.failed_candidates:
            if failure not in self.context.failed_tasks:
                self.context.failed_tasks.append(failure)
        for failure in self.provider.failed_candidate_failures:
            if failure not in self.context.failures:
                self.context.failures.append(failure)
        return tasks

    def direct_file_tasks(self, file_paths: list[str]) -> list[ArchiveTask]:
        tasks = []
        for raw_path in file_paths:
            path = os.path.abspath(os.path.normpath(raw_path))
            if not os.path.isfile(path):
                self.context.failed_tasks.append(f"{raw_path} [direct mode requires a file]")
                continue
            task = direct_file_task(path)
            if task.key in self.context.processed_keys:
                continue
            tasks.append(task)
        return tasks


def direct_file_task(path: str) -> ArchiveTask:
    path = os.path.abspath(os.path.normpath(path))
    name = os.path.basename(path)
    logical_name, ext = os.path.splitext(name)
    bag = FactBag()
    bag.set("file.path", path)
    bag.set("file.logical_name", logical_name or name)
    bag.set("file.detected_ext", ext.lower())
    bag.set("candidate.entry_path", path)
    bag.set("candidate.kind", "direct_file")
    bag.set("candidate.logical_name", logical_name or name)
    bag.set("candidate.member_paths", [path])
    bag.set("archive.format_hint", ext.lower().lstrip("."))
    try:
        bag.set("file.size", os.path.getsize(path))
    except OSError:
        pass
    return ArchiveTask.from_fact_bag(
        bag,
        score=0,
        decision=SimpleNamespace(decision="direct_file", stop_reason="cli_direct_file", matched_rules=[]),
    )
