from typing import Callable, List

from sunpack.contracts.tasks import ArchiveTask
from sunpack.rename.conflicts import next_available_path


class RenameScheduler:
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
