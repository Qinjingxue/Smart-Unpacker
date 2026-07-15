from __future__ import annotations

from dataclasses import dataclass

from sunpack_native import (
    validate_ntfs_watch_root as _native_validate_ntfs_watch_root,
    watch_candidate_for_path as _native_watch_candidate_for_path,
    watch_file_is_ready as _native_watch_file_is_ready,
)


@dataclass(frozen=True)
class WatchCandidate:
    path: str
    size: int
    mtime: float
    file_id: str = ""
    change_usn: int = 0


def scan_watch_candidates(roots: list[str], *, recursive: bool = True) -> list[WatchCandidate]:
    return _scan_filesystem_candidates(list(roots or []), bool(recursive))


def _candidate_for(path: str) -> WatchCandidate | None:
    item = _native_watch_candidate_for_path(str(path))
    return _candidate_from_native(item) if item is not None else None


def _candidate_from_native(item: dict) -> WatchCandidate:
    return WatchCandidate(
        path=str(item.get("path") or ""),
        size=int(item.get("size", 0) or 0),
        mtime=float(item.get("mtime", 0.0) or 0.0),
        file_id=str(item.get("file_id") or ""),
        change_usn=int(item.get("change_usn", 0) or 0),
    )


def _scan_filesystem_candidates(roots: list[str], recursive: bool) -> list[WatchCandidate]:
    from sunpack_native import scan_watch_candidates as native_scan_watch_candidates

    return [_candidate_from_native(item) for item in native_scan_watch_candidates(roots, recursive)]


def validate_ntfs_watch_roots(roots: list[str]) -> None:
    for root in roots:
        _native_validate_ntfs_watch_root(str(root))


def watch_file_is_ready(path: str) -> bool:
    return bool(_native_watch_file_is_ready(str(path)))
