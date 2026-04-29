from __future__ import annotations

import os
from dataclasses import dataclass

from sunpack_native import scan_watch_candidates as _native_scan_watch_candidates
from sunpack_native import watch_candidate_for_path as _native_watch_candidate_for_path


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
    return [_candidate_from_native(item) for item in _native_scan_watch_candidates(list(roots or []), bool(recursive))]


def _candidate_for(path: str) -> WatchCandidate | None:
    item = _native_watch_candidate_for_path(str(path))
    if item is None:
        return None
    return _candidate_from_native(item)


def _looks_like_archive(name: str) -> bool:
    if any(name.endswith(suffix) for suffix in WATCH_ARCHIVE_SUFFIXES):
        return True
    return False


def looks_like_archive(path: str) -> bool:
    return _looks_like_archive(os.path.basename(path).lower())


def _candidate_from_native(item: dict) -> WatchCandidate:
    return WatchCandidate(
        path=str(item.get("path") or ""),
        size=int(item.get("size", 0) or 0),
        mtime=float(item.get("mtime", 0.0) or 0.0),
    )
