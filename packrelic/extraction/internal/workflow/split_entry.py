import os
from typing import Optional

from packrelic.contracts.tasks import SplitArchiveInfo
from packrelic.relations import RelationsScheduler
from packrelic.support.path_keys import path_key


class SplitEntryResolver:
    def __init__(self, relations: RelationsScheduler | None = None):
        self.relations = relations or RelationsScheduler()

    def resolve(
        self,
        archive: str,
        all_parts: list[str],
        split_info: Optional[SplitArchiveInfo],
    ) -> tuple[str, list[str], SplitArchiveInfo]:
        split_info = split_info or SplitArchiveInfo()
        all_parts = self._dedupe_paths(list(all_parts or []) + list(split_info.parts or []) + [archive])
        entry = split_info.preferred_entry or ""

        if not entry:
            entry = self.relations.select_first_volume(all_parts)

        if not entry and self.relations.should_scan_split_siblings(
            archive,
            is_split=split_info.is_split,
            is_sfx_stub=split_info.is_sfx_stub,
        ):
            sibling_parts = self.relations.find_standard_split_siblings(archive)
            if sibling_parts:
                all_parts = self._dedupe_paths(all_parts + sibling_parts)
                entry = self.relations.select_first_volume(all_parts)

        if entry and path_key(entry) != path_key(archive):
            print(f"[SPLIT] 使用分卷入口: {entry}")
            split_info = SplitArchiveInfo(
                is_split=True,
                is_sfx_stub=split_info.is_sfx_stub or self._looks_like_sfx_stub(archive),
                parts=list(all_parts),
                preferred_entry=entry,
                source=split_info.source or "filename",
                volumes=list(split_info.volumes or []),
            )
            return entry, all_parts, split_info

        if len(all_parts) > 1 and not split_info.is_split:
            split_info = SplitArchiveInfo(
                is_split=True,
                is_sfx_stub=split_info.is_sfx_stub,
                parts=list(all_parts),
                preferred_entry=split_info.preferred_entry,
                source=split_info.source or "filename",
                volumes=list(split_info.volumes or []),
            )

        return archive, all_parts, split_info

    def _looks_like_sfx_stub(self, path: str) -> bool:
        return os.path.splitext(path)[1].lower() == ".exe"

    def _dedupe_paths(self, paths: list[str]) -> list[str]:
        deduped = []
        seen = set()
        for path in paths:
            if not path:
                continue
            key = path_key(path)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(path)
        return deduped
