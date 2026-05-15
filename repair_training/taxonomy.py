from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from repair_training.schemas import TrainingDamageLabel


TAXONOMY_SCHEMA_VERSION = 1

ZIP_DAMAGE_FAMILIES = {
    "boundary",
    "central_directory",
    "local_header",
    "zip64",
    "data_descriptor",
    "extra_field",
    "payload",
    "naming_encoding",
    "split_volume",
    "carrier_sfx",
    "conflict_duplicate",
    "salvage_partial",
    "unknown",
}

SEVEN_ZIP_DAMAGE_FAMILIES = {
    "signature_start_header",
    "next_header",
    "encoded_header",
    "pack_stream",
    "folder_stream",
    "metadata_names",
    "crc",
    "encryption_password",
    "split_volume",
    "carrier_sfx",
    "payload_partial",
    "salvage_partial",
    "unknown",
}


@dataclass(frozen=True)
class DamageZone:
    kind: str = ""
    path: str = ""
    offset: int | None = None
    size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "offset": self.offset,
            "size": self.size,
        }


@dataclass(frozen=True)
class DamageTaxonomyLabel:
    label: str
    format: str
    family: str
    zone: DamageZone = field(default_factory=DamageZone)
    severity: float = 1.0
    expected_min_steps: int = 1
    route_hints: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TAXONOMY_SCHEMA_VERSION,
            "label": self.label,
            "format": self.format,
            "family": self.family,
            "zone": self.zone.to_dict(),
            "severity": float(self.severity or 0.0),
            "expected_min_steps": int(self.expected_min_steps or 0),
            "route_hints": list(self.route_hints),
            "metadata": dict(self.metadata),
        }

    def to_training_label(self) -> TrainingDamageLabel:
        payload = self.to_dict()
        return TrainingDamageLabel(
            label=self.label,
            zone=payload["zone"],
            confidence=float(self.severity or 0.0),
            metadata={
                "schema_version": TAXONOMY_SCHEMA_VERSION,
                "format": self.format,
                "family": self.family,
                "severity": float(self.severity or 0.0),
                "expected_min_steps": int(self.expected_min_steps or 0),
                "route_hints": list(self.route_hints),
                **dict(self.metadata),
            },
        )


@dataclass(frozen=True)
class DamageTaxonomyTarget:
    format: str
    labels: list[DamageTaxonomyLabel]
    route_hints: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TAXONOMY_SCHEMA_VERSION,
            "format": self.format,
            "labels": [label.to_dict() for label in self.labels],
            "damage_labels": [label.label for label in self.labels],
            "damage_families": sorted({label.family for label in self.labels}),
            "route_hints": list(self.route_hints),
            "metadata": dict(self.metadata),
        }

    def training_labels(self) -> list[TrainingDamageLabel]:
        return [label.to_training_label() for label in self.labels]


def normalize_damage_record(record: dict[str, Any]) -> DamageTaxonomyTarget:
    fmt = _normalize_format(record.get("material_format") or record.get("format") or _format_from_input(record))
    expected_min_steps = _int(record.get("expected_min_steps"), default=1)
    route_hints = _dedupe([
        *[str(item) for item in record.get("expected_route_facts") or [] if str(item)],
        *[str(item) for item in record.get("runtime_damage_flags") or [] if str(item)],
        *[str(item) for item in record.get("damage_flags") or [] if str(item)],
    ])
    labels: list[DamageTaxonomyLabel] = []

    for mutation in record.get("corruption_plan") or []:
        if not isinstance(mutation, dict):
            continue
        labels.append(_label_from_mutation(fmt, mutation, record, expected_min_steps, route_hints))

    for flag in _dedupe([str(item) for item in [*(record.get("runtime_damage_flags") or []), *(record.get("damage_flags") or [])] if str(item)]):
        family = _family_from_text(fmt, flag)
        label = _label_name(family, flag)
        if not any(existing.label == label for existing in labels):
            labels.append(_make_label(fmt, family, label, DamageZone(kind="flag", path=flag), record, expected_min_steps, route_hints, source="flag"))

    profile = str(record.get("damage_profile") or record.get("profile") or "")
    if profile and not labels:
        family = _family_from_text(fmt, profile)
        labels.append(_make_label(fmt, family, _label_name(family, profile), DamageZone(kind="profile", path=profile), record, expected_min_steps, route_hints, source="profile"))

    if not labels:
        labels.append(_make_label(fmt, "unknown", "unknown", DamageZone(kind="unknown", path=""), record, expected_min_steps, route_hints, source="fallback"))

    return DamageTaxonomyTarget(
        format=fmt,
        labels=labels,
        route_hints=route_hints,
        metadata={
            "damage_profile": profile,
            "damage_layer": record.get("damage_layer") or record.get("profile_layer") or record.get("actual_damage_layer"),
            "oracle_strength": record.get("oracle_strength"),
            "difficulty_tags": list(record.get("difficulty_tags") or []),
        },
    )


def _label_from_mutation(
    fmt: str,
    mutation: dict[str, Any],
    record: dict[str, Any],
    expected_min_steps: int,
    route_hints: list[str],
) -> DamageTaxonomyLabel:
    zone_text = str(mutation.get("zone") or _nested(mutation, "operation", "details", "zone") or mutation.get("kind") or mutation.get("name") or "")
    family = _family_from_text(fmt, " ".join([zone_text, str(mutation.get("name") or ""), str(mutation.get("expected_effect") or "")]))
    label = _label_name(family, zone_text or str(mutation.get("name") or "mutation"))
    return _make_label(
        fmt,
        family,
        label,
        DamageZone(
            kind=_zone_kind(zone_text),
            path=zone_text,
            offset=_optional_int(mutation.get("offset")),
            size=_optional_int(mutation.get("size")),
        ),
        record,
        expected_min_steps,
        route_hints,
        source="mutation",
        extra_metadata={
            "mutation_name": mutation.get("name"),
            "expected_effect": mutation.get("expected_effect"),
            "operation": mutation.get("operation"),
        },
    )


def _make_label(
    fmt: str,
    family: str,
    label: str,
    zone: DamageZone,
    record: dict[str, Any],
    expected_min_steps: int,
    route_hints: list[str],
    *,
    source: str,
    extra_metadata: dict[str, Any] | None = None,
) -> DamageTaxonomyLabel:
    return DamageTaxonomyLabel(
        label=label,
        format=fmt,
        family=family,
        zone=zone,
        severity=_severity(record, expected_min_steps),
        expected_min_steps=expected_min_steps,
        route_hints=route_hints,
        metadata={
            "source": source,
            "damage_profile": record.get("damage_profile") or record.get("profile"),
            "damage_layer": record.get("damage_layer") or record.get("profile_layer") or record.get("actual_damage_layer"),
            "oracle_strength": record.get("oracle_strength"),
            **dict(extra_metadata or {}),
        },
    )


def _family_from_text(fmt: str, text: str) -> str:
    lowered = str(text or "").lower()
    if fmt == "zip":
        pairs = (
            ("carrier_sfx", ("sfx", "carrier", "prefix")),
            ("split_volume", ("split", "volume", "missing_volume", "sidecar")),
            ("conflict_duplicate", ("duplicate", "overlap", "conflict")),
            ("data_descriptor", ("data_descriptor", "descriptor", "bit3")),
            ("zip64", ("zip64",)),
            ("extra_field", ("extra",)),
            ("central_directory", ("central_directory", "eocd", "directory", "cd_")),
            ("local_header", ("local_header",)),
            ("naming_encoding", ("filename", "encoding", "raw_name", "utf")),
            ("payload", ("payload", "crc", "checksum", "compressed", "uncompressed")),
            ("boundary", ("tail", "trailing", "junk", "boundary", "crop")),
            ("salvage_partial", ("partial", "salvage", "truncated")),
        )
        return _family_match(lowered, pairs, ZIP_DAMAGE_FAMILIES)
    pairs = (
        ("carrier_sfx", ("sfx", "carrier", "prefix")),
        ("split_volume", ("split", "volume", "sidecar")),
        ("encryption_password", ("encrypt", "password", "wrong_password")),
        ("encoded_header", ("encoded_header",)),
        ("next_header", ("next_header",)),
        ("signature_start_header", ("signature", "start_header", "start header")),
        ("metadata_names", ("names", "utf16", "file_count", "metadata")),
        ("pack_stream", ("pack", "pack_stream")),
        ("folder_stream", ("folder", "substream")),
        ("crc", ("crc", "checksum", "stream_crc")),
        ("payload_partial", ("payload", "truncated", "partial")),
        ("salvage_partial", ("salvage",)),
    )
    return _family_match(lowered, pairs, SEVEN_ZIP_DAMAGE_FAMILIES)


def _family_match(text: str, pairs: tuple[tuple[str, tuple[str, ...]], ...], allowed: set[str]) -> str:
    for family, needles in pairs:
        if any(needle in text for needle in needles):
            return family if family in allowed else "unknown"
    return "unknown"


def _label_name(family: str, raw: str) -> str:
    path = str(raw or "").lower().replace(".", "_").replace("-", "_").replace(" ", "_")
    path = "_".join(part for part in path.split("_") if part)
    if not path or path == family:
        return family
    if path.startswith(family):
        return path
    if family == "central_directory" and "entry_count" in path:
        return "central_directory_count"
    return f"{family}/{path}"


def _zone_kind(zone: str) -> str:
    text = str(zone or "").lower()
    if "." in text:
        return text.split(".", 1)[0]
    if text:
        return text
    return "unknown"


def _severity(record: dict[str, Any], expected_min_steps: int) -> float:
    if bool(record.get("compound_profile")):
        return 1.0
    layer = str(record.get("damage_layer") or record.get("profile_layer") or record.get("actual_damage_layer") or "").lower()
    if layer == "compound" or expected_min_steps > 1:
        return 1.0
    if layer == "partial":
        return 0.75
    return 0.6


def _format_from_input(record: dict[str, Any]) -> str:
    source = record.get("damaged_input") if isinstance(record.get("damaged_input"), dict) else {}
    return str(source.get("format_hint") or source.get("format") or "")


def _normalize_format(value: Any) -> str:
    text = str(value or "").lower().lstrip(".")
    return {"7z": "seven_zip", "7zip": "seven_zip", "seven_zip": "seven_zip"}.get(text, text)


def _nested(payload: dict[str, Any], *path: str) -> Any:
    current: Any = payload
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _optional_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def _int(value: Any, *, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        if value and value not in output:
            output.append(value)
    return output
