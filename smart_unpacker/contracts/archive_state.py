from __future__ import annotations

import hashlib
import json
import base64
from dataclasses import dataclass, field
from typing import Any, Literal

from smart_unpacker.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    ArchiveInputRange,
    ArchiveInputSegment,
    ArchiveOpenMode,
)


PatchTarget = Literal["logical", "part"]
PatchOperationKind = Literal["replace_range", "truncate", "append", "insert", "delete"]


@dataclass(frozen=True)
class ArchiveSource:
    entry_path: str
    open_mode: ArchiveOpenMode = "file"
    format_hint: str = ""
    logical_name: str = ""
    parts: list[ArchiveInputPart] = field(default_factory=list)
    ranges: list[ArchiveInputRange] = field(default_factory=list)
    segment: ArchiveInputSegment | None = None
    analysis: dict[str, Any] = field(default_factory=dict)
    source_identity: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": "archive_source",
            "entry_path": self.entry_path,
            "open_mode": self.open_mode,
        }
        if self.format_hint:
            payload["format_hint"] = self.format_hint
        if self.logical_name:
            payload["logical_name"] = self.logical_name
        if self.parts:
            payload["parts"] = [part.to_dict() for part in self.parts]
        if self.ranges:
            payload["ranges"] = [item.to_dict() for item in self.ranges]
        if self.segment is not None:
            payload["segment"] = self.segment.to_dict()
        if self.analysis:
            payload["analysis"] = dict(self.analysis)
        if self.source_identity:
            payload["source_identity"] = self.source_identity
        return payload

    def to_archive_input_descriptor(self) -> ArchiveInputDescriptor:
        return ArchiveInputDescriptor(
            entry_path=self.entry_path,
            open_mode=self.open_mode,
            format_hint=self.format_hint,
            logical_name=self.logical_name,
            parts=list(self.parts),
            ranges=list(self.ranges),
            segment=self.segment,
            analysis=dict(self.analysis),
        )

    def part_paths(self) -> list[str]:
        return self.to_archive_input_descriptor().part_paths()

    def with_path_mapping(self, mapper) -> "ArchiveSource":
        return ArchiveSource.from_archive_input(
            self.to_archive_input_descriptor().with_path_mapping(mapper),
            source_identity=self.source_identity,
        )

    @classmethod
    def from_archive_input(
        cls,
        descriptor: ArchiveInputDescriptor,
        *,
        source_identity: str = "",
    ) -> "ArchiveSource":
        return cls(
            entry_path=descriptor.entry_path,
            open_mode=descriptor.open_mode,
            format_hint=descriptor.format_hint,
            logical_name=descriptor.logical_name,
            parts=list(descriptor.parts),
            ranges=list(descriptor.ranges),
            segment=descriptor.segment,
            analysis=dict(descriptor.analysis),
            source_identity=source_identity,
        )

    @classmethod
    def from_dict(
        cls,
        raw: dict[str, Any],
        *,
        archive_path: str = "",
        part_paths: list[str] | None = None,
    ) -> "ArchiveSource":
        if raw.get("kind") == "archive_source":
            raw = {**raw, "kind": "archive_input"}
        descriptor = ArchiveInputDescriptor.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
        return cls.from_archive_input(descriptor, source_identity=str(raw.get("source_identity") or ""))


@dataclass(frozen=True)
class PatchOperation:
    op: PatchOperationKind
    target: PatchTarget = "logical"
    offset: int = 0
    size: int | None = None
    part_index: int | None = None
    data_b64: str = ""
    data_ref: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "op": self.op,
            "target": self.target,
            "offset": int(self.offset),
        }
        if self.size is not None:
            payload["size"] = int(self.size)
        if self.part_index is not None:
            payload["part_index"] = int(self.part_index)
        if self.data_b64:
            payload["data_b64"] = self.data_b64
        if self.data_ref:
            payload["data_ref"] = self.data_ref
        if self.details:
            payload["details"] = dict(self.details)
        return payload

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PatchOperation":
        return cls(
            op=str(raw.get("op") or "replace_range"),  # type: ignore[arg-type]
            target=str(raw.get("target") or "logical"),  # type: ignore[arg-type]
            offset=int(raw.get("offset", 0) or 0),
            size=int(raw["size"]) if raw.get("size") is not None else None,
            part_index=int(raw["part_index"]) if raw.get("part_index") is not None else None,
            data_b64=str(raw.get("data_b64") or ""),
            data_ref=str(raw.get("data_ref") or ""),
            details=dict(raw.get("details") or {}) if isinstance(raw.get("details"), dict) else {},
        )

    @classmethod
    def replace_bytes(
        cls,
        *,
        offset: int,
        data: bytes,
        target: PatchTarget = "logical",
        details: dict[str, Any] | None = None,
    ) -> "PatchOperation":
        return cls(
            op="replace_range",
            target=target,
            offset=int(offset),
            size=len(data),
            data_b64=base64.b64encode(bytes(data)).decode("ascii"),
            details=dict(details or {}),
        )

    @classmethod
    def append_bytes(
        cls,
        data: bytes,
        *,
        target: PatchTarget = "logical",
        details: dict[str, Any] | None = None,
    ) -> "PatchOperation":
        return cls(
            op="append",
            target=target,
            offset=0,
            size=len(data),
            data_b64=base64.b64encode(bytes(data)).decode("ascii"),
            details=dict(details or {}),
        )

    @classmethod
    def delete_range(
        cls,
        *,
        offset: int,
        size: int,
        target: PatchTarget = "logical",
        details: dict[str, Any] | None = None,
    ) -> "PatchOperation":
        return cls(
            op="delete",
            target=target,
            offset=int(offset),
            size=max(0, int(size)),
            details=dict(details or {}),
        )


@dataclass(frozen=True)
class PatchPlan:
    id: str = ""
    operations: list[PatchOperation] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": "patch_plan",
            "id": self.id or self.digest(),
            "operations": [operation.to_dict() for operation in self.operations],
            "confidence": float(self.confidence),
        }
        if self.provenance:
            payload["provenance"] = dict(self.provenance)
        return payload

    def digest(self) -> str:
        return _stable_digest({
            "operations": [operation.to_dict() for operation in self.operations],
            "provenance": self.provenance,
            "confidence": self.confidence,
        })

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PatchPlan":
        operations = [
            PatchOperation.from_dict(item)
            for item in raw.get("operations") or []
            if isinstance(item, dict)
        ]
        return cls(
            id=str(raw.get("id") or ""),
            operations=operations,
            provenance=dict(raw.get("provenance") or {}) if isinstance(raw.get("provenance"), dict) else {},
            confidence=float(raw.get("confidence", 0.0) or 0.0),
        )


@dataclass(frozen=True)
class ArchiveState:
    source: ArchiveSource
    patches: list[PatchPlan] = field(default_factory=list)
    patch_digest: str = ""
    logical_name: str = ""
    format_hint: str = ""
    analysis: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": "archive_state",
            "source": self.source.to_dict(),
            "patches": [patch.to_dict() for patch in self.patches],
            "patch_digest": self.effective_patch_digest(),
        }
        if self.logical_name:
            payload["logical_name"] = self.logical_name
        if self.format_hint:
            payload["format_hint"] = self.format_hint
        if self.analysis:
            payload["analysis"] = dict(self.analysis)
        if self.verification:
            payload["verification"] = dict(self.verification)
        return payload

    def effective_patch_digest(self) -> str:
        return self.patch_digest or _stable_digest([patch.to_dict() for patch in self.patches])

    def to_archive_input_descriptor(self) -> ArchiveInputDescriptor:
        descriptor = self.source.to_archive_input_descriptor()
        if not self.format_hint and not self.logical_name:
            return descriptor
        return ArchiveInputDescriptor(
            entry_path=descriptor.entry_path,
            open_mode=descriptor.open_mode,
            format_hint=self.format_hint or descriptor.format_hint,
            logical_name=self.logical_name or descriptor.logical_name,
            parts=list(descriptor.parts),
            ranges=list(descriptor.ranges),
            segment=descriptor.segment,
            analysis=dict(descriptor.analysis),
        )

    def with_path_mapping(self, mapper) -> "ArchiveState":
        return ArchiveState(
            source=self.source.with_path_mapping(mapper),
            patches=list(self.patches),
            patch_digest=self.patch_digest,
            logical_name=self.logical_name,
            format_hint=self.format_hint,
            analysis=dict(self.analysis),
            verification=dict(self.verification),
        )

    @classmethod
    def from_archive_input(
        cls,
        descriptor: ArchiveInputDescriptor,
        *,
        patches: list[PatchPlan] | None = None,
        analysis: dict[str, Any] | None = None,
        verification: dict[str, Any] | None = None,
    ) -> "ArchiveState":
        patch_stack = list(patches or [])
        state = cls(
            source=ArchiveSource.from_archive_input(descriptor),
            patches=patch_stack,
            logical_name=descriptor.logical_name,
            format_hint=descriptor.format_hint,
            analysis=dict(analysis or {}),
            verification=dict(verification or {}),
        )
        return cls(
            source=state.source,
            patches=state.patches,
            patch_digest=state.effective_patch_digest(),
            logical_name=state.logical_name,
            format_hint=state.format_hint,
            analysis=state.analysis,
            verification=state.verification,
        )

    @classmethod
    def from_dict(
        cls,
        raw: dict[str, Any],
        *,
        archive_path: str = "",
        part_paths: list[str] | None = None,
    ) -> "ArchiveState":
        source_raw = raw.get("source")
        if isinstance(source_raw, dict):
            source = ArchiveSource.from_dict(source_raw, archive_path=archive_path, part_paths=part_paths)
        else:
            descriptor = ArchiveInputDescriptor.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
            source = ArchiveSource.from_archive_input(descriptor)
        patches = [
            PatchPlan.from_dict(item)
            for item in raw.get("patches") or raw.get("patch_stack") or []
            if isinstance(item, dict)
        ]
        state = cls(
            source=source,
            patches=patches,
            patch_digest=str(raw.get("patch_digest") or ""),
            logical_name=str(raw.get("logical_name") or source.logical_name),
            format_hint=str(raw.get("format_hint") or source.format_hint),
            analysis=dict(raw.get("analysis") or {}) if isinstance(raw.get("analysis"), dict) else {},
            verification=dict(raw.get("verification") or {}) if isinstance(raw.get("verification"), dict) else {},
        )
        if state.patch_digest:
            return state
        return cls(
            source=state.source,
            patches=state.patches,
            patch_digest=state.effective_patch_digest(),
            logical_name=state.logical_name,
            format_hint=state.format_hint,
            analysis=state.analysis,
            verification=state.verification,
        )

    @classmethod
    def from_any(
        cls,
        raw: dict[str, Any] | None,
        *,
        archive_path: str,
        part_paths: list[str] | None = None,
        format_hint: str = "",
        logical_name: str = "",
        archive_input: dict[str, Any] | None = None,
    ) -> "ArchiveState":
        if isinstance(raw, dict):
            if raw.get("kind") == "archive_state" or isinstance(raw.get("source"), dict):
                state = cls.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
                return _with_state_defaults(state, format_hint=format_hint, logical_name=logical_name)
            descriptor = ArchiveInputDescriptor.from_any(
                raw,
                archive_path=archive_path,
                part_paths=part_paths,
                format_hint=format_hint,
                logical_name=logical_name,
            )
            return cls.from_archive_input(descriptor)
        descriptor = ArchiveInputDescriptor.from_any(
            archive_input,
            archive_path=archive_path,
            part_paths=part_paths,
            format_hint=format_hint,
            logical_name=logical_name,
        )
        return cls.from_archive_input(descriptor)


def _with_state_defaults(state: ArchiveState, *, format_hint: str = "", logical_name: str = "") -> ArchiveState:
    if (state.format_hint or not format_hint) and (state.logical_name or not logical_name):
        return state
    return ArchiveState(
        source=state.source,
        patches=list(state.patches),
        patch_digest=state.effective_patch_digest(),
        logical_name=state.logical_name or logical_name,
        format_hint=state.format_hint or format_hint,
        analysis=dict(state.analysis),
        verification=dict(state.verification),
    )


def _stable_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
