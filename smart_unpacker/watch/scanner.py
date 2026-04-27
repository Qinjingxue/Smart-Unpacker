from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


WATCH_ARCHIVE_SUFFIXES = {
    ".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".zst", ".tar",
    ".tgz", ".tbz", ".tbz2", ".txz", ".tzst", ".001", ".exe",
}


@dataclass(frozen=True)
class WatchCandidate:
    path: str
    size: int
    mtime: float


def scan_watch_candidates(roots: list[str], *, recursive: bool = True) -> list[WatchCandidate]:
    candidates: list[WatchCandidate] = []
    for root in roots:
        if os.path.isfile(root):
            item = _candidate_for(root)
            if item is not None:
                candidates.append(item)
            continue
        if not os.path.isdir(root):
            continue
        if recursive:
            walker = os.walk(root)
            for current_root, _dirs, files in walker:
                for name in files:
                    item = _candidate_for(os.path.join(current_root, name))
                    if item is not None:
                        candidates.append(item)
        else:
            for item in Path(root).iterdir():
                if item.is_file():
                    candidate = _candidate_for(str(item))
                    if candidate is not None:
                        candidates.append(candidate)
    candidates.sort(key=lambda item: item.path)
    return candidates


def _candidate_for(path: str) -> WatchCandidate | None:
    lower = os.path.basename(path).lower()
    if not _looks_like_archive(lower):
        return None
    try:
        stat = os.stat(path)
    except OSError:
        return None
    if stat.st_size <= 0:
        return None
    return WatchCandidate(path=os.path.abspath(path), size=int(stat.st_size), mtime=float(stat.st_mtime))


def _looks_like_archive(name: str) -> bool:
    if any(name.endswith(suffix) for suffix in WATCH_ARCHIVE_SUFFIXES):
        return True
    return False


def looks_like_archive(path: str) -> bool:
    return _looks_like_archive(os.path.basename(path).lower())
