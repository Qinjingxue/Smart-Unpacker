import os
from typing import List

from smart_unpacker.coordinator.context import RunContext
from smart_unpacker.coordinator.output_scan import OutputScanPolicy
from smart_unpacker.extraction.scheduler import ExtractionScheduler
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.rename.scheduler import RenameScheduler


class ExtractionBatchRunner:
    def __init__(
        self,
        context: RunContext,
        extractor: ExtractionScheduler,
        output_scan_policy: OutputScanPolicy,
        rename_scheduler: RenameScheduler | None = None,
    ):
        self.context = context
        self.extractor = extractor
        self.output_scan_policy = output_scan_policy
        self.rename_scheduler = rename_scheduler or RenameScheduler()

    def prepare_tasks(self, tasks: List[ArchiveTask]):
        path_map = self.rename_scheduler.apply_renames(tasks)
        if path_map:
            for task in tasks:
                task.apply_path_mapping(path_map)

    def execute(self, tasks: List[ArchiveTask]) -> List[str]:
        if not tasks:
            return []

        self.prepare_tasks(tasks)
        tasks = self._skip_tasks_inside_batch_outputs(tasks)
        results = self.extractor.extract_tasks(tasks)
        output_dirs = []
        for task, result in results:
            output_dir = self.collect_result(task, result)
            if output_dir:
                output_dirs.append(output_dir)
        return self.output_scan_policy.scan_roots_from_outputs(output_dirs)

    def _skip_tasks_inside_batch_outputs(self, tasks: List[ArchiveTask]) -> List[ArchiveTask]:
        output_roots = []
        for task in tasks:
            output_dir = self.extractor.default_output_dir_for_task(task)
            if output_dir:
                output_roots.append((task, os.path.normcase(os.path.abspath(output_dir))))

        filtered = []
        for task in tasks:
            task_path = os.path.normcase(os.path.abspath(task.main_path))
            inside_another_output = False
            for owner, output_root in output_roots:
                if owner is task:
                    continue
                try:
                    if os.path.commonpath([task_path, output_root]) == output_root:
                        inside_another_output = True
                        break
                except ValueError:
                    continue
            if not inside_another_output:
                filtered.append(task)
        return filtered

    def collect_result(self, task: ArchiveTask, res) -> str | None:
        path = task.main_path
        out_dir = res.out_dir

        with self.context.lock:
            if res.success:
                self.context.success_count += 1
                self.context.processed_keys.add(task.key)
                self.context.unpacked_archives.append(res.all_parts or task.all_parts)
                self.context.flatten_candidates.add(out_dir)
                return out_dir
            self.context.failed_tasks.append(f"{os.path.basename(path)} [{res.error}]")
            return None
