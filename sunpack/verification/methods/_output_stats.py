import os
from dataclasses import dataclass
from typing import Any

from sunpack_native import scan_output_tree as _native_scan_output_tree
from sunpack.support.path_names import normalize_match_path


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


@dataclass(frozen=True)
class OutputInventory:
    stats: OutputStats
    files: tuple[dict[str, Any], ...] = ()
    worker_crc_available: bool = False


TRANSIENT_SUFFIXES = (
    ".tmp",
    ".temp",
    ".part",
    ".partial",
    ".crdownload",
)


def collect_output_stats(output_dir: str) -> OutputStats:
    return collect_output_inventory(output_dir).stats


def collect_output_inventory(output_dir: str, worker_result: dict[str, Any] | None = None) -> OutputInventory:
    if not output_dir:
        return OutputInventory(stats=OutputStats(exists=False, is_dir=False))
    scan = dict(_native_scan_output_tree(output_dir))
    files = [dict(item) for item in scan.get("files") or [] if isinstance(item, dict)]
    worker_files = _verified_worker_files(worker_result)
    worker_by_path = {
        normalize_match_path(str(item.get("path") or "")): item
        for item in worker_files
        if item.get("path")
    }
    merged_files: list[dict[str, Any]] = []
    for item in files:
        merged = {
            "path": str(item.get("path") or ""),
            "size": int(item.get("size", 0) or 0),
        }
        worker_item = worker_by_path.get(normalize_match_path(merged["path"]))
        if worker_item is not None:
            merged.update({
                "bytes_written": int(worker_item.get("bytes_written", merged["size"]) or 0),
                "status": str(worker_item.get("status") or "complete"),
                "crc_ok": worker_item.get("crc_ok"),
            })
            if worker_item.get("has_output_crc") and worker_item.get("output_crc32") is not None:
                merged["crc32"] = int(worker_item["output_crc32"]) & 0xFFFFFFFF
                merged["crc_source"] = "sevenzip_worker_write"
        merged_files.append(merged)
    stats = OutputStats(
        exists=bool(scan.get("exists")),
        is_dir=bool(scan.get("is_dir")),
        file_count=int(scan.get("file_count", 0) or 0),
        dir_count=int(scan.get("dir_count", 0) or 0),
        total_size=int(scan.get("total_size", 0) or 0),
        transient_file_count=int(scan.get("transient_file_count", 0) or 0),
        unreadable_count=int(scan.get("unreadable_count", 0) or 0),
        relative_paths=tuple(str(item.get("path") or "") for item in files),
    )
    return OutputInventory(
        stats=stats,
        files=tuple(merged_files),
        worker_crc_available=bool(worker_files),
    )


def output_stats_for_evidence(evidence: Any) -> OutputStats:
    return output_inventory_for_evidence(evidence).stats


def output_inventory_for_evidence(evidence: Any) -> OutputInventory:
    cached = getattr(evidence, "_output_inventory_cache", None)
    if cached is not None:
        return cached
    inventory = collect_output_inventory(
        getattr(evidence, "output_dir", ""),
        getattr(evidence, "worker_result", None),
    )
    try:
        object.__setattr__(evidence, "_output_inventory_cache", inventory)
    except Exception:
        pass
    return inventory


def output_files_for_evidence(evidence: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in output_inventory_for_evidence(evidence).files]


def _verified_worker_files(worker_result: dict[str, Any] | None) -> list[dict[str, Any]]:
    result = worker_result if isinstance(worker_result, dict) else {}
    manifest = result.get("verified_manifest") if isinstance(result.get("verified_manifest"), dict) else {}
    if result.get("status") != "ok" or not manifest.get("validated"):
        return []
    return [dict(item) for item in manifest.get("files") or [] if isinstance(item, dict)]
