from __future__ import annotations

import os

from sunpack.contracts.tasks import ArchiveTask, SplitArchiveInfo
from sunpack.relations import RelationsScheduler
from sunpack.support.path_keys import path_key


class ArchiveRelationStage:
    """Complete relation descriptors before black-box extraction."""

    def __init__(self, relations: RelationsScheduler | None = None):
        self.relations = relations or RelationsScheduler()

    def resolve_tasks(self, tasks: list[ArchiveTask]) -> None:
        for task in tasks:
            self.resolve_task(task)

    def resolve_task(self, task: ArchiveTask) -> None:
        info = task.split_info or SplitArchiveInfo()
        parts = _dedupe([*task.all_parts, *info.parts, task.main_path])
        entry = info.preferred_entry or self.relations.select_first_volume(parts)
        if not entry and self.relations.should_scan_split_siblings(
            task.main_path,
            is_split=info.is_split,
            is_sfx_stub=info.is_sfx_stub,
        ):
            parts = _dedupe([*parts, *self.relations.find_standard_split_siblings(task.main_path)])
            entry = self.relations.select_first_volume(parts)
        is_split = bool(info.is_split or len(parts) > 1 or entry and path_key(entry) != path_key(task.main_path))
        task.all_parts = parts
        task.split_info = SplitArchiveInfo(
            is_split=is_split,
            is_sfx_stub=bool(info.is_sfx_stub or os.path.splitext(task.main_path)[1].lower() == ".exe" and is_split),
            parts=parts,
            preferred_entry=entry or task.main_path,
            source=info.source or ("coordinator" if is_split else ""),
            volumes=list(info.volumes or []),
        )


def _dedupe(paths: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if not path:
            continue
        key = path_key(path)
        if key in seen:
            continue
        seen.add(key)
        output.append(path)
    return output
