from typing import Optional

from sunpack.contracts.tasks import SplitArchiveInfo
from sunpack.support.path_keys import path_key


class SplitEntryResolver:
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
            entry = archive

        if entry and path_key(entry) != path_key(archive):
            print(f"[SPLIT] 使用分卷入口: {entry}")
            split_info = SplitArchiveInfo(
                is_split=True,
                is_sfx_stub=split_info.is_sfx_stub,
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
