import os
from typing import Any

from smart_unpacker.detection.pipeline.processors.modules.zip_structure import inspect_zip_local_header
from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.registry import register_processor

MAGIC_SIGNATURES = (
    (b"7z\xbc\xaf\x27\x1c", "7z", ".7z"),
    (b"Rar!\x1a\x07\x01\x00", "rar", ".rar"),
    (b"Rar!\x1a\x07\x00", "rar", ".rar"),
    (b"PK\x03\x04", "zip", ".zip"),
    (b"PK\x05\x06", "zip", ".zip"),
    (b"PK\x07\x08", "zip", ".zip"),
    (b"\x1f\x8b", "gz", ".gz"),
    (b"BZh", "bz2", ".bz2"),
    (b"\xfd7zXZ\x00", "xz", ".xz"),
)


def empty_identity() -> dict[str, Any]:
    return {
        "is_archive_like": False,
        "format": "",
        "detected_ext": "",
        "offset": 0,
        "mode": "",
        "confidence": "none",
        "requires_confirmation": False,
        "evidence": [],
        "candidates": [],
        "zip_local_header": {},
    }


def _candidate(
    archive_format: str,
    detected_ext: str,
    offset: int,
    mode: str,
    confidence: str,
    requires_confirmation: bool,
    evidence: list[str],
    zip_local_header: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "format": archive_format,
        "detected_ext": detected_ext,
        "offset": int(offset or 0),
        "mode": mode,
        "confidence": confidence,
        "requires_confirmation": bool(requires_confirmation),
        "evidence": list(evidence),
        "zip_local_header": zip_local_header or {},
    }


def _identity_from_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    identity = empty_identity()
    identity.update({
        "is_archive_like": True,
        "format": candidate.get("format") or "",
        "detected_ext": candidate.get("detected_ext") or "",
        "offset": int(candidate.get("offset") or 0),
        "mode": candidate.get("mode") or "",
        "confidence": candidate.get("confidence") or "none",
        "requires_confirmation": bool(candidate.get("requires_confirmation")),
        "evidence": list(candidate.get("evidence") or []),
        "candidates": [candidate],
        "zip_local_header": candidate.get("zip_local_header") or {},
    })
    return identity


def _format_from_ext(ext: str) -> str:
    return ext[1:].lower() if ext.startswith(".") else ext.lower()


def _embedded_mode(analysis: dict[str, Any], path_ext: str) -> str:
    mode = analysis.get("mode") or ""
    if path_ext == ".exe" and mode == "loose_scan":
        return "sfx_hint"
    return mode


def empty_magic_start() -> dict[str, Any]:
    return {
        "matched": False,
        "format": "",
        "detected_ext": "",
        "offset": 0,
        "confidence": "none",
        "requires_confirmation": False,
        "evidence": [],
        "zip_local_header": {},
    }


def analyze_archive_magic_start(path: str, magic_bytes: bytes | None) -> dict[str, Any]:
    prefix = magic_bytes or b""
    for magic, archive_format, detected_ext in MAGIC_SIGNATURES:
        if not prefix.startswith(magic):
            continue
        zip_header = inspect_zip_local_header(path, 0) if magic == b"PK\x03\x04" else {}
        confidence = "strong"
        requires_confirmation = False
        evidence = [f"magic_start:{archive_format}"]
        if magic == b"PK\x03\x04" and not zip_header.get("plausible"):
            confidence = "medium"
            requires_confirmation = True
            evidence.append("zip_local_header:implausible")
        return {
            "matched": True,
            "format": archive_format,
            "detected_ext": detected_ext,
            "offset": 0,
            "confidence": confidence,
            "requires_confirmation": requires_confirmation,
            "evidence": evidence,
            "zip_local_header": zip_header,
        }
    return empty_magic_start()


def _candidate_from_magic(path: str, magic_bytes: bytes | None) -> dict[str, Any] | None:
    magic_start = analyze_archive_magic_start(path, magic_bytes)
    if not magic_start.get("matched"):
        return None
    return _candidate(
        str(magic_start.get("format") or ""),
        str(magic_start.get("detected_ext") or ""),
        int(magic_start.get("offset") or 0),
        "magic_start",
        str(magic_start.get("confidence") or "strong"),
        bool(magic_start.get("requires_confirmation")),
        list(magic_start.get("evidence") or []),
        magic_start.get("zip_local_header") or {},
    )


def _candidate_from_embedded(path: str, analysis: dict[str, Any]) -> dict[str, Any] | None:
    if not analysis.get("found"):
        return None

    detected_ext = analysis.get("detected_ext") or ""
    archive_format = _format_from_ext(detected_ext)
    path_ext = os.path.splitext(path)[1].lower()
    mode = _embedded_mode(analysis, path_ext)
    confidence = "strong" if mode == "carrier_tail" else "medium"
    requires_confirmation = mode in {"loose_scan", "sfx_hint"}
    evidence = [f"{mode}:{archive_format}"]
    zip_header = analysis.get("zip_local_header") or {}
    if detected_ext == ".zip":
        if zip_header.get("plausible"):
            evidence.append("zip_local_header:plausible")
        else:
            confidence = "medium"
            requires_confirmation = True
            evidence.append("zip_local_header:implausible")

    return _candidate(
        archive_format,
        detected_ext,
        int(analysis.get("offset") or 0),
        mode,
        confidence,
        requires_confirmation,
        evidence,
        zip_header,
    )


def build_archive_identity(
    path: str,
    magic_bytes: bytes | None = None,
    embedded_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    magic_candidate = _candidate_from_magic(path, magic_bytes)
    if magic_candidate:
        return _identity_from_candidate(magic_candidate)

    embedded_candidate = _candidate_from_embedded(path, embedded_analysis or {})
    if embedded_candidate:
        return _identity_from_candidate(embedded_candidate)

    return empty_identity()


@register_processor(
    "archive_identity",
    input_facts={"file.path", "file.magic_bytes", "embedded_archive.analysis"},
    output_facts={"archive.identity"},
    schemas={
        "archive.identity": {
            "type": "dict",
            "description": "Unified archive identity guess produced from magic bytes and embedded archive evidence facts.",
        },
    },
)
def process_archive_identity(context: FactProcessorContext) -> dict[str, Any]:
    facts = context.fact_bag
    return build_archive_identity(
        facts.get("file.path") or "",
        facts.get("file.magic_bytes") or b"",
        facts.get("embedded_archive.analysis") or {},
    )
