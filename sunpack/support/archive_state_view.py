from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState

from sunpack_native import (
    archive_state_size_native as _native_archive_state_size,
    archive_state_to_bytes_native as _native_archive_state_to_bytes,
)


class UnsupportedArchivePatch(ValueError):
    pass


@dataclass(frozen=True)
class ByteViewStats:
    read_bytes: int
    cache_hits: int = 0


class ArchiveStateByteView:
    def __init__(self, state: ArchiveState):
        self.state = state
        self.path = state.source.entry_path
        self._read_bytes = 0
        self.size = int(_native_archive_state_size(state.source.to_dict(), [patch.to_dict() for patch in state.patches]))

    def read_at(self, offset: int, size: int) -> bytes:
        offset = max(0, int(offset))
        size = max(0, int(size))
        if size <= 0 or offset >= self.size:
            return b""
        end = min(self.size, offset + size)
        patch = {
            "operations": [
                {"op": "delete", "offset": end, "size": max(0, self.size - end)},
                {"op": "delete", "offset": 0, "size": offset},
            ],
        }
        data = bytes(_native_archive_state_to_bytes(
            self.state.source.to_dict(),
            [*[item.to_dict() for item in self.state.patches], patch],
        ))
        self._read_bytes += len(data)
        return data

    def read_tail(self, size: int) -> bytes:
        size = max(0, int(size))
        return self.read_at(max(0, self.size - size), size)

    def stats(self) -> ByteViewStats:
        return ByteViewStats(read_bytes=self._read_bytes, cache_hits=0)

    def to_bytes(self) -> bytes:
        return bytes(_native_archive_state_to_bytes(self.state.source.to_dict(), [patch.to_dict() for patch in self.state.patches]))


def archive_state_to_bytes(state: ArchiveState) -> bytes:
    return ArchiveStateByteView(state).to_bytes()


def archive_state_from_source_input(
    source_input: dict[str, Any],
    *,
    format_hint: str = "",
    logical_name: str = "",
) -> ArchiveState:
    descriptor = ArchiveInputDescriptor.from_any(
        source_input,
        archive_path=str(source_input.get("path") or source_input.get("archive_path") or ""),
        part_paths=[
            str(item.get("path") or "")
            for item in source_input.get("ranges", [])
            if isinstance(item, dict) and item.get("path")
        ] or None,
        format_hint=format_hint or str(source_input.get("format_hint") or source_input.get("format") or ""),
        logical_name=logical_name,
    )
    return ArchiveState.from_archive_input(descriptor)
