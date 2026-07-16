from __future__ import annotations

import hashlib
import json
import base64
from dataclasses import dataclass, field
from typing import Any, Literal

from sunpack.contracts.archive_input import (
    ArchiveInputDescriptor,
    ArchiveInputPart,
    ArchiveInputRange,
    ArchiveInputSegment,
    ArchiveOpenMode,
)


PatchTarget = Literal["logical", "part"]
PatchOperationKind = Literal["replace_range", "truncate", "append", "insert", "delete"]
PATCH_SCHEMA_VERSION = 2


@dataclass(frozen=True)
class ArchiveSource:
    entry_path: str
    open_mode: ArchiveOpenMode = "file"
    format_hint: str = ""
    logical_name: str = ""
    volume_style: str = ""
    password: str = ""
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
        if self.volume_style:
            payload["volume_style"] = self.volume_style
        if self.password:
            payload["password"] = self.password
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
            volume_style=self.volume_style,
            password=self.password,
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
            volume_style=descriptor.volume_style,
            password=descriptor.password,
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
    schema_version: int = PATCH_SCHEMA_VERSION
    target: PatchTarget = "logical"
    offset: int = 0
    size: int | None = None
    part_index: int | None = None
    data_b64: str = ""
    data_ref: str = ""
    expected_b64: str = ""
    expected_sha256: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": int(self.schema_version or PATCH_SCHEMA_VERSION),
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
        if self.expected_b64:
            payload["expected_b64"] = self.expected_b64
        if self.expected_sha256:
            payload["expected_sha256"] = self.expected_sha256
        if self.details:
            payload["details"] = dict(self.details)
        return payload

    def digest_payload(self) -> dict[str, Any]:
        payload = self.to_dict()
        if self.details:
            payload["details"] = _stable_patch_value(self.details)
        return payload

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PatchOperation":
        return cls(
            op=str(raw.get("op") or "replace_range"),  # type: ignore[arg-type]
            schema_version=int(raw.get("schema_version") or 1),
            target=str(raw.get("target") or "logical"),  # type: ignore[arg-type]
            offset=int(raw.get("offset", 0) or 0),
            size=int(raw["size"]) if raw.get("size") is not None else None,
            part_index=int(raw["part_index"]) if raw.get("part_index") is not None else None,
            data_b64=str(raw.get("data_b64") or ""),
            data_ref=str(raw.get("data_ref") or ""),
            expected_b64=str(raw.get("expected_b64") or ""),
            expected_sha256=str(raw.get("expected_sha256") or ""),
            details=dict(raw.get("details") or {}) if isinstance(raw.get("details"), dict) else {},
        )

    @classmethod
    def replace_bytes(
        cls,
        *,
        offset: int,
        data: bytes,
        target: PatchTarget = "logical",
        expected: bytes | None = None,
        expected_sha256: str = "",
        details: dict[str, Any] | None = None,
    ) -> "PatchOperation":
        return cls(
            op="replace_range",
            target=target,
            offset=int(offset),
            size=len(data),
            data_b64=base64.b64encode(bytes(data)).decode("ascii"),
            expected_b64=base64.b64encode(bytes(expected)).decode("ascii") if expected is not None else "",
            expected_sha256=str(expected_sha256 or ""),
            details=dict(details or {}),
        )

    @classmethod
    def append_bytes(
        cls,
        data: bytes,
        *,
        target: PatchTarget = "logical",
        expected: bytes | None = None,
        expected_sha256: str = "",
        details: dict[str, Any] | None = None,
    ) -> "PatchOperation":
        return cls(
            op="append",
            target=target,
            offset=0,
            size=len(data),
            data_b64=base64.b64encode(bytes(data)).decode("ascii"),
            expected_b64=base64.b64encode(bytes(expected)).decode("ascii") if expected is not None else "",
            expected_sha256=str(expected_sha256 or ""),
            details=dict(details or {}),
        )

    @classmethod
    def delete_range(
        cls,
        *,
        offset: int,
        size: int,
        target: PatchTarget = "logical",
        expected: bytes | None = None,
        expected_sha256: str = "",
        details: dict[str, Any] | None = None,
    ) -> "PatchOperation":
        return cls(
            op="delete",
            target=target,
            offset=int(offset),
            size=max(0, int(size)),
            expected_b64=base64.b64encode(bytes(expected)).decode("ascii") if expected is not None else "",
            expected_sha256=str(expected_sha256 or ""),
            details=dict(details or {}),
        )


@dataclass(frozen=True)
class PatchPlan:
    id: str = ""
    schema_version: int = PATCH_SCHEMA_VERSION
    module: str = ""
    format: str = ""
    action_type: str = "apply_patch"
    operations: list[PatchOperation] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        module = self.effective_module()
        payload: dict[str, Any] = {
            "kind": "patch_plan",
            "schema_version": int(self.schema_version or PATCH_SCHEMA_VERSION),
            "id": self.id or self.digest(),
            "action_type": self.action_type or "apply_patch",
            "operations": [operation.to_dict() for operation in self.operations],
            "confidence": float(self.confidence),
        }
        if module:
            payload["module"] = module
        if self.format:
            payload["format"] = self.format
        if self.provenance:
            payload["provenance"] = dict(self.provenance)
        return payload

    def digest(self) -> str:
        return _stable_digest(self.digest_payload())

    def effective_module(self) -> str:
        return str(self.module or self.provenance.get("module") or "")

    def digest_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "module": self.effective_module(),
            "format": self.format,
            "action_type": self.action_type,
            "operations": [operation.digest_payload() for operation in self.operations],
            "provenance": _stable_patch_provenance(self.provenance),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PatchPlan":
        operations = [
            PatchOperation.from_dict(item)
            for item in raw.get("operations") or []
            if isinstance(item, dict)
        ]
        provenance = dict(raw.get("provenance") or {}) if isinstance(raw.get("provenance"), dict) else {}
        return cls(
            id=str(raw.get("id") or ""),
            schema_version=int(raw.get("schema_version") or 1),
            module=str(raw.get("module") or provenance.get("module") or ""),
            format=str(raw.get("format") or ""),
            action_type=str(raw.get("action_type") or "apply_patch"),
            operations=operations,
            provenance=provenance,
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
    knowledge: dict[str, Any] = field(default_factory=dict)

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
        if self.knowledge:
            payload["knowledge"] = dict(self.knowledge)
        return payload

    def effective_patch_digest(self) -> str:
        return _stable_digest({
            "schema_version": PATCH_SCHEMA_VERSION,
            "patches": [patch.digest_payload() for patch in self.patches],
        })

    def with_patches(self, patches: list[PatchPlan]) -> "ArchiveState":
        return ArchiveState(
            source=self.source,
            patches=list(patches),
            patch_digest="",
            logical_name=self.logical_name,
            format_hint=self.format_hint,
            analysis=dict(self.analysis),
            verification=dict(self.verification),
            knowledge=dict(self.knowledge),
        )

    def push_patch(self, patch: PatchPlan) -> "ArchiveState":
        return self.with_patches([*self.patches, patch])

    def pop_patch(self) -> "ArchiveState":
        if not self.patches:
            return self
        return self.with_patches(list(self.patches[:-1]))

    def patch_depth(self) -> int:
        return len(self.patches)

    def last_patch(self) -> PatchPlan | None:
        return self.patches[-1] if self.patches else None

    def to_archive_input_descriptor(self) -> ArchiveInputDescriptor:
        descriptor = self.source.to_archive_input_descriptor()
        if not self.format_hint and not self.logical_name:
            return descriptor
        return ArchiveInputDescriptor(
            entry_path=descriptor.entry_path,
            open_mode=descriptor.open_mode,
            format_hint=self.format_hint or descriptor.format_hint,
            logical_name=self.logical_name or descriptor.logical_name,
            volume_style=descriptor.volume_style,
            password=descriptor.password,
            parts=list(descriptor.parts),
            ranges=list(descriptor.ranges),
            segment=descriptor.segment,
            analysis=dict(descriptor.analysis),
        )

    def with_path_mapping(self, mapper) -> "ArchiveState":
        return ArchiveState(
            source=self.source.with_path_mapping(mapper),
            patches=list(self.patches),
            patch_digest=self.effective_patch_digest(),
            logical_name=self.logical_name,
            format_hint=self.format_hint,
            analysis=dict(self.analysis),
            verification=dict(self.verification),
            knowledge=dict(self.knowledge),
        )

    @classmethod
    def from_archive_input(
        cls,
        descriptor: ArchiveInputDescriptor,
        *,
        patches: list[PatchPlan] | None = None,
        analysis: dict[str, Any] | None = None,
        verification: dict[str, Any] | None = None,
        knowledge: dict[str, Any] | None = None,
    ) -> "ArchiveState":
        patch_stack = list(patches or [])
        state = cls(
            source=ArchiveSource.from_archive_input(descriptor),
            patches=patch_stack,
            logical_name=descriptor.logical_name,
            format_hint=descriptor.format_hint,
            analysis=dict(analysis or {}),
            verification=dict(verification or {}),
            knowledge=dict(knowledge or {}),
        )
        return cls(
            source=state.source,
            patches=state.patches,
            patch_digest=state.effective_patch_digest(),
            logical_name=state.logical_name,
            format_hint=state.format_hint,
            analysis=state.analysis,
            verification=state.verification,
            knowledge=state.knowledge,
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
            knowledge=_knowledge_from_raw(raw),
        )
        computed_digest = state.effective_patch_digest()
        return cls(
            source=state.source,
            patches=state.patches,
            patch_digest=computed_digest,
            logical_name=state.logical_name,
            format_hint=state.format_hint,
            analysis=state.analysis,
            verification=state.verification,
            knowledge=state.knowledge,
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
        knowledge=dict(state.knowledge),
    )


def _knowledge_from_raw(raw: dict[str, Any]) -> dict[str, Any]:
    knowledge = raw.get("knowledge")
    if isinstance(knowledge, dict):
        return dict(knowledge)
    analysis = raw.get("analysis")
    if isinstance(analysis, dict) and isinstance(analysis.get("knowledge"), dict):
        return dict(analysis["knowledge"])
    return {}


def _stable_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _stable_patch_provenance(value: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    ignored = {
        "confidence",
        "diagnostics",
        "runtime",
        "runtime_diagnostics",
        "created_at",
        "created_step",
        "timestamp",
    }
    return {
        str(key): _stable_patch_value(item)
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        if str(key) not in ignored
    }


def _stable_patch_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _stable_patch_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key) not in {"confidence", "diagnostics", "runtime", "timestamp"}
        }
    if isinstance(value, (list, tuple)):
        return [_stable_patch_value(item) for item in value]
    return value
