import os
from typing import Any, Dict, Iterable

from smart_unpacker.coordinator.context import RunContext
from smart_unpacker.postprocess.internal.cleanup import ArchiveCleanup
from smart_unpacker.postprocess.internal.flatten import DirectoryFlattener


class PostProcessActions:
    def __init__(self, config: Dict[str, Any], context: RunContext | None = None, language: str = "en"):
        self.config = config
        self.context = context
        self.cleanup_mode = config.get("post_extract", {}).get("archive_cleanup_mode", "recycle")
        self.cleanup = ArchiveCleanup(mode=self.cleanup_mode, language=language)
        self.flattener = DirectoryFlattener()

    def apply(
        self,
        cleanup_archives: bool = True,
        flatten_outputs: bool | None = None,
        archives_to_clean: Iterable[Iterable[str]] | None = None,
        flatten_targets: Iterable[str] | None = None,
    ):
        if cleanup_archives:
            self.cleanup.cleanup_success_archives(self._consume_archives_to_clean(archives_to_clean))

        if flatten_outputs is None:
            flatten_outputs = self.config.get("post_extract", {}).get("flatten_single_directory", True)
        if flatten_outputs:
            for target in self._consume_flatten_targets(flatten_targets):
                if os.path.exists(target):
                    self.flattener.flatten_dirs(target)

    def cleanup_archive_file(self, path: str, reason: str = "[CLEAN]"):
        self.cleanup.cleanup_archive_file(path, reason)

    def _consume_archives_to_clean(self, archives_to_clean: Iterable[Iterable[str]] | None) -> list[list[str]]:
        if archives_to_clean is not None:
            return [list(parts) for parts in archives_to_clean]
        if self.context is None:
            return []
        archives = self.context.unpacked_archives
        self.context.unpacked_archives = []
        return archives

    def _consume_flatten_targets(self, flatten_targets: Iterable[str] | None) -> list[str]:
        if flatten_targets is not None:
            return sorted(flatten_targets, key=lambda item: item.count(os.sep))
        if self.context is None:
            return []
        targets = sorted(self.context.flatten_candidates, key=lambda item: item.count(os.sep))
        self.context.flatten_candidates.clear()
        return targets
