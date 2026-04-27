from __future__ import annotations

from pathlib import Path
from typing import Any

from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputRange


def verifier_input(
    archive_path: str,
    *,
    part_paths: list[str] | None = None,
    archive_input: dict[str, Any] | None = None,
) -> tuple[str, list[dict[str, Any]] | None]:
    if not archive_input:
        return archive_path, None

    descriptor = ArchiveInputDescriptor.from_dict(
        archive_input,
        archive_path=archive_path,
        part_paths=part_paths,
    )
    if descriptor.open_mode in {"file", "native_volumes", "staged_volumes", "sfx_with_volumes"}:
        return descriptor.entry_path or archive_path, None

    ranges = _descriptor_ranges(descriptor)
    if not ranges:
        return descriptor.entry_path or archive_path, None
    if len(ranges) == 1 and _is_whole_file_range(ranges[0]):
        return ranges[0].path, None
    return descriptor.entry_path or archive_path, [item.to_dict() for item in ranges]


def _descriptor_ranges(descriptor: ArchiveInputDescriptor) -> list[ArchiveInputRange]:
    if descriptor.ranges:
        return list(descriptor.ranges)
    return [part.range for part in descriptor.parts if part.range is not None]


def _is_whole_file_range(item: ArchiveInputRange) -> bool:
    if int(item.start or 0) != 0:
        return False
    if item.end is None:
        return True
    try:
        return Path(item.path).stat().st_size == int(item.end)
    except OSError:
        return False
