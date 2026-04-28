from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Any

from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor
from smart_unpacker.contracts.archive_state import ArchiveState, PatchOperation

from smart_unpacker_native import repair_read_file_range as _native_read_file_range


class UnsupportedArchivePatch(ValueError):
    pass


@dataclass(frozen=True)
class ByteViewStats:
    read_bytes: int
    cache_hits: int = 0


@dataclass(frozen=True)
class _Range:
    path: str
    start: int
    length: int


@dataclass(frozen=True)
class _Segment:
    kind: str
    length: int
    path: str = ""
    source_start: int = 0
    data: bytes = b""


class ArchiveStateByteView:
    def __init__(self, state: ArchiveState):
        self.state = state
        self.path = state.source.entry_path
        self._ranges = _ranges_for_descriptor(state.source.to_archive_input_descriptor())
        self._read_bytes = 0
        self._segments = self._apply_patches(
            [_Segment(kind="range", path=item.path, source_start=item.start, length=item.length) for item in self._ranges],
            [operation for patch in state.patches for operation in patch.operations],
        )
        self.size = sum(item.length for item in self._segments)

    def read_at(self, offset: int, size: int) -> bytes:
        offset = max(0, int(offset))
        size = max(0, int(size))
        if size <= 0 or offset >= self.size:
            return b""
        end = min(self.size, offset + size)
        result = bytearray()
        cursor = 0
        for segment in self._segments:
            segment_start = cursor
            segment_end = cursor + segment.length
            cursor = segment_end
            if segment_end <= offset:
                continue
            if segment_start >= end:
                break
            take_start = max(offset, segment_start) - segment_start
            take_end = min(end, segment_end) - segment_start
            if take_end <= take_start:
                continue
            if segment.kind == "bytes":
                result.extend(segment.data[take_start:take_end])
            else:
                result.extend(_read_range(segment.path, segment.source_start + take_start, segment.source_start + take_end))
        data = bytes(result)
        self._read_bytes += len(data)
        return data

    def read_tail(self, size: int) -> bytes:
        size = max(0, int(size))
        return self.read_at(max(0, self.size - size), size)

    def stats(self) -> ByteViewStats:
        return ByteViewStats(read_bytes=self._read_bytes, cache_hits=0)

    def to_bytes(self) -> bytes:
        return self.read_at(0, self.size)

    def _apply_patches(self, segments: list[_Segment], operations: list[PatchOperation]) -> list[_Segment]:
        output = list(segments)
        for operation in operations:
            op = operation.op
            if operation.target != "logical":
                raise UnsupportedArchivePatch(f"unsupported patch target for byte view: {operation.target}")
            if op == "replace_range":
                data = _operation_data(operation)
                size = len(data) if operation.size is None else int(operation.size)
                if size != len(data):
                    raise UnsupportedArchivePatch("replace_range patch must not change logical size")
                output = _replace_segments(output, int(operation.offset), size, data)
            elif op == "truncate":
                output = _truncate_segments(output, int(operation.offset))
            elif op == "append":
                data = _operation_data(operation)
                if data:
                    output.append(_Segment(kind="bytes", length=len(data), data=data))
            elif op == "insert":
                data = _operation_data(operation)
                output = _insert_segments(output, int(operation.offset), data)
            elif op == "delete":
                if operation.size is None:
                    raise UnsupportedArchivePatch("delete patch requires size")
                output = _delete_segments(output, int(operation.offset), int(operation.size))
            else:
                raise UnsupportedArchivePatch(f"unknown patch operation: {op}")
        return [segment for segment in output if segment.length > 0]


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


def _ranges_for_descriptor(descriptor: ArchiveInputDescriptor) -> list[_Range]:
    if descriptor.open_mode == "file":
        return [_whole_file_range(descriptor.entry_path)]
    if descriptor.open_mode == "file_range":
        if descriptor.parts and descriptor.parts[0].range is not None:
            item = descriptor.parts[0].range
            return [_range(item.path, item.start, item.end)]
        if descriptor.segment is not None:
            return [_range(descriptor.entry_path, descriptor.segment.start, descriptor.segment.end)]
        return [_whole_file_range(descriptor.entry_path)]
    if descriptor.open_mode == "concat_ranges" and descriptor.ranges:
        return [_range(item.path, item.start, item.end) for item in descriptor.ranges]
    if descriptor.parts:
        ranges = []
        for part in descriptor.parts:
            if part.range is not None:
                ranges.append(_range(part.range.path, part.range.start, part.range.end))
            elif part.path:
                ranges.append(_whole_file_range(part.path))
        return ranges
    return [_whole_file_range(descriptor.entry_path)]


def _whole_file_range(path: str) -> _Range:
    return _range(path, 0, None)


def _range(path: str, start: int, end: int | None) -> _Range:
    start = max(0, int(start or 0))
    file_size = os.path.getsize(path)
    effective_end = file_size if end is None else min(file_size, max(start, int(end)))
    return _Range(path=path, start=start, length=max(0, effective_end - start))


def _read_range(path: str, start: int, end: int) -> bytes:
    return bytes(_native_read_file_range(str(path), int(start), int(end)))


def _operation_data(operation: PatchOperation) -> bytes:
    if operation.data_ref:
        raise UnsupportedArchivePatch("data_ref patch payloads are not supported by ArchiveStateByteView yet")
    if not operation.data_b64:
        return b""
    return base64.b64decode(operation.data_b64.encode("ascii"))


def _replace_segments(segments: list[_Segment], offset: int, size: int, data: bytes) -> list[_Segment]:
    if offset < 0 or size < 0 or offset + size > _segments_size(segments):
        raise UnsupportedArchivePatch("replace_range patch is outside the current virtual archive")
    before = _slice_segments(segments, 0, offset)
    after = _slice_segments(segments, offset + size, _segments_size(segments))
    return [*before, _Segment(kind="bytes", length=len(data), data=data), *after]


def _insert_segments(segments: list[_Segment], offset: int, data: bytes) -> list[_Segment]:
    total = _segments_size(segments)
    if offset < 0 or offset > total:
        raise UnsupportedArchivePatch("insert patch is outside the current virtual archive")
    if not data:
        return list(segments)
    before = _slice_segments(segments, 0, offset)
    after = _slice_segments(segments, offset, total)
    return [*before, _Segment(kind="bytes", length=len(data), data=data), *after]


def _delete_segments(segments: list[_Segment], offset: int, size: int) -> list[_Segment]:
    total = _segments_size(segments)
    if offset < 0 or size < 0 or offset + size > total:
        raise UnsupportedArchivePatch("delete patch is outside the current virtual archive")
    before = _slice_segments(segments, 0, offset)
    after = _slice_segments(segments, offset + size, total)
    return [*before, *after]


def _truncate_segments(segments: list[_Segment], size: int) -> list[_Segment]:
    return _slice_segments(segments, 0, max(0, int(size)))


def _slice_segments(segments: list[_Segment], start: int, end: int) -> list[_Segment]:
    result: list[_Segment] = []
    cursor = 0
    for segment in segments:
        segment_start = cursor
        segment_end = cursor + segment.length
        cursor = segment_end
        if segment_end <= start:
            continue
        if segment_start >= end:
            break
        take_start = max(start, segment_start) - segment_start
        take_end = min(end, segment_end) - segment_start
        if take_end <= take_start:
            continue
        if segment.kind == "bytes":
            result.append(_Segment(kind="bytes", length=take_end - take_start, data=segment.data[take_start:take_end]))
        else:
            result.append(_Segment(
                kind="range",
                length=take_end - take_start,
                path=segment.path,
                source_start=segment.source_start + take_start,
            ))
    return result


def _segments_size(segments: list[_Segment]) -> int:
    return sum(item.length for item in segments)
