from typing import Callable, List

from sunpack.contracts.tasks import ArchiveTask
from sunpack.rename.internal.volume_normalizer import SplitVolumeNormalizer, StagedSplit
from sunpack.rename.conflicts import next_available_path


class RenameScheduler:
    def __init__(self):
        self.volume_normalizer = SplitVolumeNormalizer()

    def normalize_split_group(self, task: ArchiveTask, startupinfo=None) -> StagedSplit:
        return self.volume_normalizer.normalize(
            task.main_path,
            list(task.all_parts or [task.main_path]),
            startupinfo=startupinfo,
            volume_entries=list(task.split_info.volumes or []),
        )

    def normalize_archive_paths(
        self,
        entry_path: str,
        all_parts: list[str] | None = None,
        startupinfo=None,
        volume_entries: list[dict] | None = None,
    ) -> StagedSplit:
        return self.volume_normalizer.normalize(
            entry_path,
            list(all_parts or [entry_path]),
            startupinfo=startupinfo,
            volume_entries=volume_entries,
        )

    def cleanup_normalized_split_group(self, staged: StagedSplit):
        self.volume_normalizer.cleanup(staged)

    def build_output_dir_resolver(
        self,
        tasks: List[ArchiveTask],
        default_output_dir_for_task: Callable[[ArchiveTask], str],
    ) -> Callable[[ArchiveTask], str]:
        resolved_dirs = {}
        reserved: set[str] = set()
        for task in tasks:
            default_dir = default_output_dir_for_task(task)
            resolved_dirs[id(task)] = next_available_path(default_dir, reserved)

        return lambda task: resolved_dirs[id(task)]
