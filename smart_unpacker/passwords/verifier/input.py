from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor
from smart_unpacker_native import repair_concat_ranges_to_file


def fast_verifier_archive_path(
    archive_path: str,
    *,
    part_paths: list[str] | None = None,
    archive_input: dict[str, Any] | None = None,
) -> tuple[str, bool]:
    if not archive_input:
        return archive_path, False

    descriptor = ArchiveInputDescriptor.from_dict(
        archive_input,
        archive_path=archive_path,
        part_paths=part_paths,
    )
    if descriptor.open_mode in {"file", "native_volumes", "staged_volumes", "sfx_with_volumes"}:
        return descriptor.entry_path or archive_path, False

    if descriptor.open_mode == "concat_ranges":
        return descriptor.entry_path or archive_path, False

    ranges = descriptor.ranges
    if not ranges and descriptor.parts:
        ranges = [part.range for part in descriptor.parts if part.range is not None]
    if not ranges:
        return descriptor.entry_path or archive_path, False
    if len(ranges) == 1 and _is_whole_file_range(ranges[0]):
        return ranges[0].path, False

    suffix = _suffix_for_format(descriptor.format_hint) or Path(descriptor.entry_path or archive_path).suffix or ".bin"
    temp = tempfile.NamedTemporaryFile(prefix="smart_unpacker_pw_", suffix=suffix, delete=False)
    temp_path = temp.name
    temp.close()
    repair_concat_ranges_to_file([item.to_dict() for item in ranges], temp_path)
    return temp_path, True


def cleanup_fast_verifier_path(path: str, temporary: bool) -> None:
    if not temporary:
        return
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        pass


def _suffix_for_format(format_hint: str) -> str:
    normalized = (format_hint or "").lower().lstrip(".")
    if normalized in {"zip", "rar", "7z"}:
        return "." + normalized
    return ""


def _is_whole_file_range(item) -> bool:
    if int(item.start or 0) != 0:
        return False
    if item.end is None:
        return True
    try:
        return Path(item.path).stat().st_size == int(item.end)
    except OSError:
        return False
