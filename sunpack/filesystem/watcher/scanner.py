from __future__ import annotations

import os
from dataclasses import dataclass

from sunpack_native import watch_candidate_for_path as _native_watch_candidate_for_path


@dataclass(frozen=True)
class WatchCandidate:
    path: str
    size: int
    mtime: float


def scan_watch_candidates(roots: list[str], *, recursive: bool = True) -> list[WatchCandidate]:
    return _scan_filesystem_candidates(list(roots or []), bool(recursive))


def _candidate_for(path: str) -> WatchCandidate | None:
    item = _native_watch_candidate_for_path(str(path))
    if item is None:
        return _candidate_from_stat(path)
    return _candidate_from_native(item)


def _candidate_from_native(item: dict) -> WatchCandidate:
    return WatchCandidate(
        path=str(item.get("path") or ""),
        size=int(item.get("size", 0) or 0),
        mtime=float(item.get("mtime", 0.0) or 0.0),
    )


def _scan_filesystem_candidates(roots: list[str], recursive: bool) -> list[WatchCandidate]:
    candidates = []
    for root in roots:
        path = os.path.abspath(str(root))
        if os.path.isfile(path):
            candidate = _candidate_from_stat(path)
            if candidate is not None:
                candidates.append(candidate)
            continue
        if not os.path.isdir(path):
            continue
        if recursive:
            for dirpath, _dirnames, filenames in os.walk(path):
                for filename in filenames:
                    candidate = _candidate_from_stat(os.path.join(dirpath, filename))
                    if candidate is not None:
                        candidates.append(candidate)
        else:
            try:
                names = os.listdir(path)
            except OSError:
                continue
            for name in names:
                candidate_path = os.path.join(path, name)
                if os.path.isfile(candidate_path):
                    candidate = _candidate_from_stat(candidate_path)
                    if candidate is not None:
                        candidates.append(candidate)
    return candidates


def _candidate_from_stat(path: str) -> WatchCandidate | None:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    if not os.path.isfile(path):
        return None
    return WatchCandidate(
        path=os.path.abspath(path),
        size=int(stat.st_size),
        mtime=float(stat.st_mtime),
    )
