import re
from pathlib import Path
from typing import Any

from sunpack.filesystem.filters.base import ScanCandidate, ScanDecision, keep, prune, reject


class BlacklistScanFilter:
    name = "blacklist"
    stage = "path"

    def __init__(self, patterns=None, blocked_extensions=None, prune_dirs=None):
        self.patterns = [str(pattern) for pattern in (patterns or []) if isinstance(pattern, str)]
        self.prune_dirs = [str(pattern) for pattern in (prune_dirs or []) if isinstance(pattern, str)]
        self.blocked_extensions = {
            ext if ext.startswith(".") else f".{ext}"
            for ext in (str(item).strip().lower() for item in (blocked_extensions or []))
            if ext
        }

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(
            patterns=config.get("patterns") or [],
            blocked_extensions=config.get("blocked_extensions") or [],
            prune_dirs=config.get("prune_dirs") or [],
        )

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        path = candidate.path
        ext = path.suffix.lower()
        if candidate.kind == "file" and ext and ext in self.blocked_extensions:
            return reject(f"Blocked extension: {ext}")

        candidates = self._path_candidates(path)
        if candidate.kind == "dir":
            for pattern in self.prune_dirs:
                if self._matches(pattern, candidates):
                    return prune(f"Pruned directory: {pattern}")

        for pattern in self.patterns:
            if self._matches(pattern, candidates):
                if candidate.kind == "dir":
                    return prune(f"Hit blacklist: {pattern}")
                return reject(f"Hit blacklist: {pattern}")
        return keep()

    def _path_candidates(self, path: Path) -> list[str]:
        candidates = [
            path.name,
            str(path.parent),
            str(path),
        ]
        return [item.replace("\\", "/") for item in candidates if item]

    def _matches(self, pattern: str, candidates: list[str]) -> bool:
        return any(re.search(pattern, item, re.IGNORECASE) for item in candidates)
