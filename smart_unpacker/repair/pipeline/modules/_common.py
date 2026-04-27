from __future__ import annotations

from pathlib import Path
import shutil
from typing import Any

try:
    from smart_unpacker_native import (
        repair_concat_ranges_to_bytes as _native_concat_ranges_to_bytes,
        repair_concat_ranges_to_file as _native_concat_ranges_to_file,
        repair_copy_range_to_file as _native_copy_range_to_file,
        repair_patch_file as _native_patch_file,
        repair_read_file_range as _native_read_file_range,
        repair_write_candidate as _native_write_candidate,
    )
except ImportError:  # pragma: no cover - exercised when native extension is absent
    _native_concat_ranges_to_bytes = None
    _native_concat_ranges_to_file = None
    _native_copy_range_to_file = None
    _native_patch_file = None
    _native_read_file_range = None
    _native_write_candidate = None


def load_source_bytes(source_input: dict[str, Any]) -> bytes:
    kind = str(source_input.get("kind") or "file")
    if kind == "file":
        if _native_read_file_range is not None:
            return bytes(_native_read_file_range(str(source_input["path"]), 0, None))
        return Path(source_input["path"]).read_bytes()
    if kind == "file_range":
        path = str(source_input["path"])
        start = int(source_input.get("start") or 0)
        end = source_input.get("end")
        end_int = None if end is None else int(end)
        if _native_read_file_range is not None:
            return bytes(_native_read_file_range(path, start, end_int))
        with Path(path).open("rb") as handle:
            handle.seek(start)
            if end is None:
                return handle.read()
            return handle.read(max(0, end_int - start))
    if kind == "concat_ranges":
        ranges = list(source_input.get("ranges") or [])
        if _native_concat_ranges_to_bytes is not None:
            return bytes(_native_concat_ranges_to_bytes(ranges))
        chunks = []
        for item in ranges:
            chunks.append(load_source_bytes({"kind": "file_range", **item}))
        return b"".join(chunks)
    raise ValueError(f"unsupported repair input kind: {kind}")


def write_candidate(data: bytes, workspace: str, filename: str) -> str:
    if _native_write_candidate is not None:
        return str(_native_write_candidate(data, workspace, filename))
    path = Path(workspace) / filename
    _atomic_write(path, data)
    return str(path)


def copy_range_to_file(source_path: str, start: int, end: int | None, output_path: str) -> str:
    if _native_copy_range_to_file is not None:
        return str(_native_copy_range_to_file(source_path, int(start), None if end is None else int(end), output_path))
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_name(f".{output.name}.tmp")
    try:
        with Path(source_path).open("rb") as source, temp.open("wb") as target:
            source.seek(int(start))
            remaining = None if end is None else max(0, int(end) - int(start))
            _copy_limited(source, target, remaining)
        _replace(temp, output)
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    return str(output)


def concat_ranges_to_file(ranges: list[dict[str, Any]], output_path: str) -> str:
    if _native_concat_ranges_to_file is not None:
        return str(_native_concat_ranges_to_file(ranges, output_path))
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_name(f".{output.name}.tmp")
    try:
        with temp.open("wb") as target:
            for item in ranges:
                with Path(item["path"]).open("rb") as source:
                    start = int(item.get("start") or 0)
                    end = item.get("end")
                    source.seek(start)
                    _copy_limited(source, target, None if end is None else max(0, int(end) - start))
        _replace(temp, output)
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    return str(output)


def patch_file(source_path: str, patches: list[dict[str, Any]], output_path: str) -> str:
    if _native_patch_file is not None:
        return str(_native_patch_file(source_path, patches, output_path))
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_name(f".{output.name}.tmp")
    try:
        shutil.copyfile(source_path, temp)
        with temp.open("r+b") as handle:
            for patch in patches:
                handle.seek(int(patch["offset"]))
                handle.write(bytes(patch["data"]))
        _replace(temp, output)
    except Exception:
        temp.unlink(missing_ok=True)
        raise
    return str(output)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    try:
        temp.write_bytes(data)
        _replace(temp, path)
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def _copy_limited(source, target, remaining: int | None) -> None:
    while True:
        size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
        if size <= 0:
            return
        chunk = source.read(size)
        if not chunk:
            return
        target.write(chunk)
        if remaining is not None:
            remaining -= len(chunk)


def _replace(temp: Path, output: Path) -> None:
    if output.exists():
        output.unlink()
    temp.replace(output)
