import os
from dataclasses import dataclass
from typing import Any

from packrelic_native import scan_output_tree as _native_scan_output_tree


@dataclass(frozen=True)
class OutputStats:
    exists: bool
    is_dir: bool
    file_count: int = 0
    dir_count: int = 0
    total_size: int = 0
    transient_file_count: int = 0
    unreadable_count: int = 0
    relative_paths: tuple[str, ...] = ()


TRANSIENT_SUFFIXES = (
    ".tmp",
    ".temp",
    ".part",
    ".partial",
    ".crdownload",
)


def collect_output_stats(output_dir: str) -> OutputStats:
    if not output_dir:
        return OutputStats(exists=False, is_dir=False)
    scan = dict(_native_scan_output_tree(output_dir))
    files = [dict(item) for item in scan.get("files") or [] if isinstance(item, dict)]
    return OutputStats(
        exists=bool(scan.get("exists")),
        is_dir=bool(scan.get("is_dir")),
        file_count=int(scan.get("file_count", 0) or 0),
        dir_count=int(scan.get("dir_count", 0) or 0),
        total_size=int(scan.get("total_size", 0) or 0),
        transient_file_count=int(scan.get("transient_file_count", 0) or 0),
        unreadable_count=int(scan.get("unreadable_count", 0) or 0),
        relative_paths=tuple(str(item.get("path") or "") for item in files),
    )


def output_stats_for_evidence(evidence: Any) -> OutputStats:
    cached = getattr(evidence, "_output_stats_cache", None)
    if cached is not None:
        return cached
    stats = collect_output_stats(getattr(evidence, "output_dir", ""))
    try:
        object.__setattr__(evidence, "_output_stats_cache", stats)
    except Exception:
        pass
    return stats
