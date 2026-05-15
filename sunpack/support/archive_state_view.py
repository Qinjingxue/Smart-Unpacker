from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState

from sunpack_native import (
    archive_state_size_native as _native_archive_state_size,
    archive_state_to_bytes_native as _native_archive_state_to_bytes,
)


class UnsupportedArchivePatch(ValueError):
    pass


class ArchivePatchValidationError(UnsupportedArchivePatch):
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
        self._validated = False
        self.size = int(_native_archive_state_size(state.source.to_dict(), [patch.to_dict() for patch in state.patches]))

    def read_at(self, offset: int, size: int, validate: bool = True) -> bytes:
        if validate:
            self._validate()
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

    def read_tail(self, size: int, validate: bool = True) -> bytes:
        size = max(0, int(size))
        return self.read_at(max(0, self.size - size), size, validate=validate)

    def stats(self) -> ByteViewStats:
        return ByteViewStats(read_bytes=self._read_bytes, cache_hits=0)

    def to_bytes(self, validate: bool = True) -> bytes:
        if validate:
            self._validate()
        return bytes(_native_archive_state_to_bytes(self.state.source.to_dict(), [patch.to_dict() for patch in self.state.patches]))

    def materialize(self, path: str | Path, validate: bool = True) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.to_bytes(validate=validate))
        return target

    def with_popped_patch(self) -> "ArchiveStateByteView":
        return ArchiveStateByteView(self.state.pop_patch())

    def _validate(self) -> None:
        if self._validated:
            return
        _validate_patch_stack(self.state)
        self._validated = True


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


def _validate_patch_stack(state: ArchiveState) -> None:
    source = state.source.to_dict()
    applied: list[dict[str, Any]] = []
    for patch_index, patch in enumerate(state.patches):
        patch_prefix: list[dict[str, Any]] = []
        for operation_index, operation in enumerate(patch.operations):
            current = bytes(_native_archive_state_to_bytes(source, [*applied, {"operations": patch_prefix}]))
            _validate_operation(
                current,
                operation.to_dict(),
                patch_index=patch_index,
                operation_index=operation_index,
            )
            patch_prefix.append(operation.to_dict())
        applied.append(patch.to_dict())


def _validate_operation(
    current: bytes,
    operation: dict[str, Any],
    *,
    patch_index: int,
    operation_index: int,
) -> None:
    expected_b64 = str(operation.get("expected_b64") or "")
    expected_sha256 = str(operation.get("expected_sha256") or "")
    if not expected_b64 and not expected_sha256:
        return
    expected = None
    if expected_b64:
        try:
            expected = base64.b64decode(expected_b64.encode("ascii"), validate=True)
        except Exception as exc:
            raise ArchivePatchValidationError(
                f"invalid expected_b64 at patch {patch_index} operation {operation_index}: {exc}"
            ) from exc
    expected_len = len(expected) if expected is not None else _expected_length(operation)
    offset = max(0, int(operation.get("offset") or 0))
    op = str(operation.get("op") or "replace_range")
    if op == "append":
        offset = len(current)
    actual = current[offset:] if expected_len is None else current[offset:offset + expected_len]
    if expected is not None:
        if actual != expected:
            raise ArchivePatchValidationError(
                f"patch precondition failed at patch {patch_index} operation {operation_index}: expected bytes do not match"
            )
    if expected_sha256 and hashlib.sha256(actual).hexdigest() != expected_sha256:
        raise ArchivePatchValidationError(
            f"patch precondition failed at patch {patch_index} operation {operation_index}: expected sha256 does not match"
        )


def _expected_length(operation: dict[str, Any]) -> int | None:
    op = str(operation.get("op") or "replace_range")
    if op in {"replace_range", "delete"} and operation.get("size") is not None:
        return max(0, int(operation.get("size") or 0))
    if op == "insert":
        return 0
    if op == "append":
        return 0
    return None
