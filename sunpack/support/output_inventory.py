from __future__ import annotations

import os
from dataclasses import asdict, dataclass
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
    root: str
    stats: OutputStats
    files: tuple[dict[str, Any], ...] = ()
    worker_crc_available: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "root": self.root,
            "stats": {
                **asdict(self.stats),
                "relative_paths": list(self.stats.relative_paths),
            },
            "files": [dict(item) for item in self.files],
            "worker_crc_available": self.worker_crc_available,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None, *, expected_root: str = "") -> "OutputInventory | None":
        if not isinstance(payload, dict) or int(payload.get("version", 0) or 0) != 1:
            return None
        root = str(payload.get("root") or "")
        if expected_root and _path_key(root) != _path_key(expected_root):
            return None
        raw_stats = payload.get("stats") if isinstance(payload.get("stats"), dict) else {}
        files = tuple(dict(item) for item in payload.get("files") or [] if isinstance(item, dict))
        stats = OutputStats(
            exists=bool(raw_stats.get("exists")),
            is_dir=bool(raw_stats.get("is_dir")),
            file_count=int(raw_stats.get("file_count", 0) or 0),
            dir_count=int(raw_stats.get("dir_count", 0) or 0),
            total_size=int(raw_stats.get("total_size", 0) or 0),
            transient_file_count=int(raw_stats.get("transient_file_count", 0) or 0),
            unreadable_count=int(raw_stats.get("unreadable_count", 0) or 0),
            relative_paths=tuple(str(item) for item in raw_stats.get("relative_paths") or []),
        )
        return cls(
            root=root,
            stats=stats,
            files=files,
            worker_crc_available=bool(payload.get("worker_crc_available")),
        )


def collect_output_inventory(
    output_dir: str,
    worker_result: dict[str, Any] | None = None,
) -> OutputInventory:
    root = os.path.abspath(output_dir) if output_dir else ""
    if not output_dir:
        return OutputInventory(root=root, stats=OutputStats(exists=False, is_dir=False))
    worker_inventory = _complete_worker_inventory(worker_result)
    if worker_inventory is not None:
        files, inventory = worker_inventory
        merged_files = tuple({
            "path": str(item.get("output_path") or item.get("path") or ""),
            "size": int(item.get("size", item.get("bytes_written", 0)) or 0),
            "bytes_written": int(item.get("bytes_written", 0) or 0),
            "status": str(item.get("status") or "complete"),
            "crc_ok": item.get("crc_ok"),
            **({"crc32": int(item["output_crc32"]) & 0xFFFFFFFF, "crc_source": "sevenzip_worker_write"}
               if item.get("has_output_crc") and item.get("output_crc32") is not None else {}),
        } for item in files)
        return OutputInventory(
            root=root,
            stats=OutputStats(
                exists=True, is_dir=True,
                file_count=int(inventory["file_count"]), dir_count=int(inventory["dir_count"]),
                total_size=int(inventory["total_size"]), transient_file_count=0, unreadable_count=0,
                relative_paths=tuple(str(item["path"]) for item in merged_files),
            ),
            files=merged_files,
            worker_crc_available=bool(files),
        )
    scan = dict(_native_scan_output_tree(output_dir))
    files = [dict(item) for item in scan.get("files") or [] if isinstance(item, dict)]
    worker_files = verified_worker_files(worker_result)
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
        root=root,
        stats=stats,
        files=tuple(merged_files),
        worker_crc_available=bool(worker_files),
    )


def verified_worker_files(worker_result: dict[str, Any] | None) -> list[dict[str, Any]]:
    result = worker_result if isinstance(worker_result, dict) else {}
    manifest = result.get("verified_manifest") if isinstance(result.get("verified_manifest"), dict) else {}
    if result.get("status") != "ok" or not manifest.get("validated"):
        return []
    return [dict(item) for item in manifest.get("files") or [] if isinstance(item, dict)]


def _complete_worker_inventory(worker_result: dict[str, Any] | None) -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
    result = worker_result if isinstance(worker_result, dict) else {}
    manifest = result.get("verified_manifest") if isinstance(result.get("verified_manifest"), dict) else {}
    inventory = manifest.get("inventory") if isinstance(manifest.get("inventory"), dict) else {}
    files = verified_worker_files(result)
    if (
        not inventory.get("complete")
        or int(inventory.get("file_count", -1)) != len(files)
        or any(str(item.get("status") or "") != "complete" for item in files)
    ):
        return None
    return files, inventory


def _path_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path)) if path else ""
