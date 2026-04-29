from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


ArchiveOpenMode = Literal[
    "file",
    "file_range",
    "concat_ranges",
    "native_volumes",
    "staged_volumes",
    "sfx_with_volumes",
]


@dataclass(frozen=True)
class ArchiveInputRange:
    path: str
    start: int = 0
    end: int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "path": self.path,
            "start": int(self.start),
        }
        if self.end is not None:
            payload["end"] = int(self.end)
        return payload


@dataclass(frozen=True)
class ArchiveInputPart:
    path: str
    role: str = "main"
    volume_number: int | None = None
    range: ArchiveInputRange | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "path": self.path,
            "role": self.role,
        }
        if self.volume_number is not None:
            payload["volume_number"] = int(self.volume_number)
        if self.range is not None:
            payload.update({
                "start": int(self.range.start),
            })
            if self.range.end is not None:
                payload["end"] = int(self.range.end)
        return payload


@dataclass(frozen=True)
class ArchiveInputSegment:
    start: int = 0
    end: int | None = None
    confidence: float | None = None
    source: str = "analysis"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "start": int(self.start),
            "source": self.source,
        }
        if self.end is not None:
            payload["end"] = int(self.end)
        if self.confidence is not None:
            payload["confidence"] = float(self.confidence)
        return payload


@dataclass(frozen=True)
class ArchiveInputDescriptor:
    entry_path: str
    open_mode: ArchiveOpenMode = "file"
    format_hint: str = ""
    logical_name: str = ""
    parts: list[ArchiveInputPart] = field(default_factory=list)
    ranges: list[ArchiveInputRange] = field(default_factory=list)
    segment: ArchiveInputSegment | None = None
    analysis: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": "archive_input",
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
        return payload

    def to_source_input(self) -> dict[str, Any]:
        if self.open_mode == "file":
            return {"kind": "file", "path": self.entry_path, "format_hint": self.format_hint}
        if self.open_mode == "file_range":
            item_range = self._primary_range()
            if item_range is None:
                return {"kind": "file", "path": self.entry_path, "format_hint": self.format_hint}
            payload: dict[str, Any] = {
                "kind": "file_range",
                "path": item_range.path,
                "start": int(item_range.start),
                "format_hint": self.format_hint,
            }
            if item_range.end is not None:
                payload["end"] = int(item_range.end)
            return payload
        if self.open_mode == "concat_ranges" and self.ranges:
            return {
                "kind": "concat_ranges",
                "ranges": [item.to_dict() for item in self.ranges],
                "format_hint": self.format_hint,
            }
        if self.parts:
            return {
                "kind": "concat_ranges",
                "ranges": [
                    {"path": part.path, "start": 0, "end": None}
                    for part in self.parts
                ],
                "format_hint": self.format_hint,
            }
        return {"kind": "file", "path": self.entry_path, "format_hint": self.format_hint}

    def part_paths(self) -> list[str]:
        if self.open_mode == "concat_ranges" and self.ranges:
            return list(dict.fromkeys(item.path for item in self.ranges if item.path))
        if self.parts:
            return list(dict.fromkeys(part.path for part in self.parts if part.path))
        return [self.entry_path] if self.entry_path else []

    def with_path_mapping(self, mapper) -> "ArchiveInputDescriptor":
        parts = [
            ArchiveInputPart(
                path=mapper(part.path),
                role=part.role,
                volume_number=part.volume_number,
                range=ArchiveInputRange(
                    path=mapper(part.range.path),
                    start=part.range.start,
                    end=part.range.end,
                ) if part.range is not None else None,
            )
            for part in self.parts
        ]
        ranges = [
            ArchiveInputRange(path=mapper(item.path), start=item.start, end=item.end)
            for item in self.ranges
        ]
        return ArchiveInputDescriptor(
            entry_path=mapper(self.entry_path),
            open_mode=self.open_mode,
            format_hint=self.format_hint,
            logical_name=self.logical_name,
            parts=parts,
            ranges=ranges,
            segment=self.segment,
            analysis=dict(self.analysis),
        )

    def _primary_range(self) -> ArchiveInputRange | None:
        if self.parts:
            part = self.parts[0]
            if part.range is not None:
                return part.range
        if self.segment is not None:
            return ArchiveInputRange(path=self.entry_path, start=self.segment.start, end=self.segment.end)
        return None

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, archive_path: str = "", part_paths: list[str] | None = None) -> "ArchiveInputDescriptor":
        open_mode = str(raw.get("open_mode") or raw.get("kind") or "file")
        if open_mode == "archive_input":
            open_mode = "file"
        format_hint = str(raw.get("format_hint") or raw.get("format") or "")
        entry_path = str(raw.get("entry_path") or archive_path)
        parts = []
        for item in raw.get("parts") or []:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or entry_path)
            end_raw = item.get("end", item.get("end_offset"))
            start = int(item.get("start", item.get("start_offset", 0)) or 0)
            part_range = None
            if start or end_raw is not None:
                part_range = ArchiveInputRange(
                    path=path,
                    start=start,
                    end=int(end_raw) if end_raw is not None else None,
                )
            parts.append(ArchiveInputPart(
                path=path,
                role=str(item.get("role") or "main"),
                volume_number=int(item["volume_number"]) if item.get("volume_number") is not None else None,
                range=part_range,
            ))
        ranges = []
        for item in raw.get("ranges") or []:
            if not isinstance(item, dict):
                continue
            end_raw = item.get("end", item.get("end_offset"))
            ranges.append(ArchiveInputRange(
                path=str(item.get("path") or entry_path),
                start=int(item.get("start", item.get("start_offset", 0)) or 0),
                end=int(end_raw) if end_raw is not None else None,
            ))
        segment = None
        segment_raw = raw.get("segment")
        if isinstance(segment_raw, dict):
            end_raw = segment_raw.get("end", segment_raw.get("end_offset"))
            confidence_raw = segment_raw.get("confidence")
            segment = ArchiveInputSegment(
                start=int(segment_raw.get("start", segment_raw.get("start_offset", 0)) or 0),
                end=int(end_raw) if end_raw is not None else None,
                confidence=float(confidence_raw) if confidence_raw is not None else None,
                source=str(segment_raw.get("source") or "analysis"),
            )
        if not parts and not ranges and part_paths:
            parts = [
                ArchiveInputPart(path=str(path), role="volume" if index else "main", volume_number=index + 1)
                for index, path in enumerate(part_paths)
            ]
        return cls(
            entry_path=entry_path,
            open_mode=open_mode,  # type: ignore[arg-type]
            format_hint=format_hint,
            logical_name=str(raw.get("logical_name") or ""),
            parts=parts,
            ranges=ranges,
            segment=segment,
            analysis=dict(raw.get("analysis") or {}) if isinstance(raw.get("analysis"), dict) else {},
        )

    @classmethod
    def from_source_input(cls, raw: dict[str, Any], *, archive_path: str, part_paths: list[str] | None = None) -> "ArchiveInputDescriptor":
        kind = str(raw.get("kind") or "file").lower()
        format_hint = str(raw.get("format_hint") or raw.get("format") or "")
        if kind == "file":
            path = str(raw.get("path") or raw.get("archive_path") or archive_path)
            parts = [ArchiveInputPart(path=path, role="main", volume_number=1)]
            return cls(entry_path=path, open_mode="file", format_hint=format_hint, parts=parts)
        if kind == "file_range":
            path = str(raw.get("path") or archive_path)
            start = int(raw.get("start", raw.get("start_offset", 0)) or 0)
            end_raw = raw.get("end", raw.get("end_offset"))
            end = int(end_raw) if end_raw is not None else None
            return cls(
                entry_path=path,
                open_mode="file_range",
                format_hint=format_hint,
                parts=[ArchiveInputPart(path=path, range=ArchiveInputRange(path=path, start=start, end=end))],
                segment=ArchiveInputSegment(start=start, end=end),
            )
        if kind == "concat_ranges":
            ranges = []
            for item in raw.get("ranges") or []:
                if not isinstance(item, dict):
                    continue
                path = str(item.get("path") or archive_path)
                end_raw = item.get("end", item.get("end_offset"))
                ranges.append(ArchiveInputRange(
                    path=path,
                    start=int(item.get("start", item.get("start_offset", 0)) or 0),
                    end=int(end_raw) if end_raw is not None else None,
                ))
            return cls(
                entry_path=archive_path,
                open_mode="concat_ranges",
                format_hint=format_hint,
                ranges=ranges,
            )
        parts = [
            ArchiveInputPart(path=str(path), role="volume" if index else "main", volume_number=index + 1)
            for index, path in enumerate(part_paths or [archive_path])
        ]
        return cls(entry_path=archive_path, open_mode="file" if len(parts) <= 1 else "native_volumes", format_hint=format_hint, parts=parts)

    @classmethod
    def from_parts(
        cls,
        *,
        archive_path: str,
        part_paths: list[str] | None = None,
        format_hint: str = "",
        logical_name: str = "",
        open_mode: ArchiveOpenMode | None = None,
    ) -> "ArchiveInputDescriptor":
        paths = list(part_paths or [archive_path])
        mode: ArchiveOpenMode = open_mode or ("file" if len(paths) <= 1 else "native_volumes")
        return cls(
            entry_path=archive_path,
            open_mode=mode,
            format_hint=format_hint,
            logical_name=logical_name,
            parts=[
                ArchiveInputPart(path=str(path), role="volume" if index else "main", volume_number=index + 1)
                for index, path in enumerate(paths)
            ],
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
    ) -> "ArchiveInputDescriptor":
        if isinstance(raw, dict):
            if raw.get("kind") == "archive_input" or raw.get("open_mode"):
                descriptor = cls.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
            else:
                descriptor = cls.from_source_input(raw, archive_path=archive_path, part_paths=part_paths)
            if not descriptor.format_hint and format_hint:
                return cls(
                    entry_path=descriptor.entry_path,
                    open_mode=descriptor.open_mode,
                    format_hint=format_hint,
                    logical_name=descriptor.logical_name or logical_name,
                    parts=list(descriptor.parts),
                    ranges=list(descriptor.ranges),
                    segment=descriptor.segment,
                    analysis=dict(descriptor.analysis),
                )
            return descriptor
        return cls.from_parts(
            archive_path=archive_path,
            part_paths=part_paths,
            format_hint=format_hint,
            logical_name=logical_name,
        )


@dataclass(frozen=True)
class ArchiveFormatState:
    detected: str = ""
    selected: str = ""
    hint: str = ""
    confidence: float = 0.0
    status: str = ""


@dataclass(frozen=True)
class ArchiveRelationState:
    kind: str = "file"
    is_split: bool = False
    is_sfx: bool = False
    volumes_complete: bool | None = None
    missing_indices: list[int] = field(default_factory=list)
    missing_reason: str = ""


@dataclass(frozen=True)
class ArchiveLayoutState:
    start_offset: int = 0
    end_offset: int | None = None
    has_prefix: bool = False
    has_suffix: bool = False
    embedded: bool = False


@dataclass(frozen=True)
class ArchiveIntegrityState:
    damage_flags: list[str] = field(default_factory=list)
    checksum_error: bool = False
    payload_error: bool = False
    partial: bool = False


@dataclass(frozen=True)
class ArchiveSecurityState:
    encrypted: bool = False
    password_required: bool = False
    wrong_password: bool = False
    password: str = ""


@dataclass(frozen=True)
class ArchiveRepairState:
    repaired: bool = False
    rounds: list[dict[str, Any]] = field(default_factory=list)
    terminal_reason: str = ""


@dataclass(frozen=True)
class ArchiveRuntimeState:
    output_dir: str = ""
    codepage: str = ""
    diagnostics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ArchiveDescriptor:
    id: str
    logical_name: str
    source: ArchiveInputDescriptor
    format: ArchiveFormatState = field(default_factory=ArchiveFormatState)
    relation: ArchiveRelationState = field(default_factory=ArchiveRelationState)
    layout: ArchiveLayoutState = field(default_factory=ArchiveLayoutState)
    integrity: ArchiveIntegrityState = field(default_factory=ArchiveIntegrityState)
    security: ArchiveSecurityState = field(default_factory=ArchiveSecurityState)
    repair: ArchiveRepairState = field(default_factory=ArchiveRepairState)
    runtime: ArchiveRuntimeState = field(default_factory=ArchiveRuntimeState)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "logical_name": self.logical_name,
            "source": self.source.to_dict(),
            "format": self.format.__dict__,
            "relation": self.relation.__dict__,
            "layout": self.layout.__dict__,
            "integrity": self.integrity.__dict__,
            "security": self.security.__dict__,
            "repair": self.repair.__dict__,
            "runtime": self.runtime.__dict__,
        }
