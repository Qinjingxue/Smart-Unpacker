from __future__ import annotations

from typing import Any

from smart_unpacker_native import (
    repair_concat_ranges_to_bytes as _native_concat_ranges_to_bytes,
    repair_concat_ranges_to_file as _native_concat_ranges_to_file,
    repair_copy_range_to_file as _native_copy_range_to_file,
    repair_patch_file as _native_patch_file,
    repair_read_file_range as _native_read_file_range,
    repair_write_candidate as _native_write_candidate,
)


def load_source_bytes(source_input: dict[str, Any]) -> bytes:
    kind = str(source_input.get("kind") or "file")
    if kind == "file":
        return bytes(_native_read_file_range(str(source_input["path"]), 0, None))
    if kind == "file_range":
        path = str(source_input["path"])
        start = int(source_input.get("start") or 0)
        end = source_input.get("end")
        end_int = None if end is None else int(end)
        return bytes(_native_read_file_range(path, start, end_int))
    if kind == "concat_ranges":
        ranges = list(source_input.get("ranges") or [])
        return bytes(_native_concat_ranges_to_bytes(ranges))
    raise ValueError(f"unsupported repair input kind: {kind}")


def write_candidate(data: bytes, workspace: str, filename: str) -> str:
    return str(_native_write_candidate(data, workspace, filename))


def copy_range_to_file(source_path: str, start: int, end: int | None, output_path: str) -> str:
    return str(_native_copy_range_to_file(source_path, int(start), None if end is None else int(end), output_path))


def concat_ranges_to_file(ranges: list[dict[str, Any]], output_path: str) -> str:
    return str(_native_concat_ranges_to_file(ranges, output_path))


def patch_file(source_path: str, patches: list[dict[str, Any]], output_path: str) -> str:
    return str(_native_patch_file(source_path, patches, output_path))


def copy_source_prefix_to_file(source_input: dict[str, Any], length: int, output_path: str) -> str:
    length = max(0, int(length))
    kind = str(source_input.get("kind") or "file")
    if kind == "file":
        return copy_range_to_file(str(source_input["path"]), 0, length, output_path)
    if kind == "file_range":
        start = int(source_input.get("start") or 0)
        declared_end = source_input.get("end")
        end = start + length
        if declared_end is not None:
            end = min(end, int(declared_end))
        return copy_range_to_file(str(source_input["path"]), start, end, output_path)
    if kind == "concat_ranges":
        ranges = _take_concat_prefix(list(source_input.get("ranges") or []), length)
        return concat_ranges_to_file(ranges, output_path)
    raise ValueError(f"unsupported repair input kind: {kind}")


def _take_concat_prefix(ranges: list[dict[str, Any]], length: int) -> list[dict[str, Any]]:
    result = []
    remaining = length
    for item in ranges:
        if remaining <= 0:
            break
        start = int(item.get("start") or 0)
        end = item.get("end")
        if end is None:
            take_end = start + remaining
        else:
            available = max(0, int(end) - start)
            take_end = start + min(available, remaining)
        if take_end > start:
            result.append({**item, "start": start, "end": take_end})
            remaining -= take_end - start
    return result
