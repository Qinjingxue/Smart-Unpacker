from __future__ import annotations

from sunpack.support.runtime_route_evidence import (
    _filter_seven_zip_conflicting_runtime_flags,
    _filter_zip_conflicting_runtime_flags,
    seven_zip_route_evidence_flags,
    zip_route_evidence_flags,
)
from dataclasses import dataclass, field
from typing import Any

from sunpack.repair.coverage import ArchiveCoverageView, coverage_view_from_payload
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.support.archive_formats import canonical_format as _normalize_format
from sunpack.repair.job import RepairJob
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.support import archive_knowledge_projection as knowledge_view


@dataclass(frozen=True)
class RepairContext:
    source_input: dict[str, Any]
    format: str
    confidence: float = 0.0
    categories: tuple[str, ...] = ()
    damage_flags: tuple[str, ...] = ()
    fuzzy_hints: tuple[str, ...] = ()
    offset_hints: tuple[dict[str, Any], ...] = ()
    failure_stage: str = ""
    failure_kind: str = ""
    failure_status: str = ""
    native_status: str = ""
    operation_result_name: str = ""
    failed_item: str = ""
    structure_evidence: Any = None
    archive_coverage: ArchiveCoverageView = field(default_factory=ArchiveCoverageView)
    prepass: dict[str, Any] = field(default_factory=dict)
    fuzzy_profile: dict[str, Any] = field(default_factory=dict)
    extraction_failure: dict[str, Any] = field(default_factory=dict)
    extraction_diagnostics: dict[str, Any] = field(default_factory=dict)
    route_evidence_flags: tuple[str, ...] = ()
    repair_history_flags: tuple[str, ...] = ()
    residual_damage_flags: tuple[str, ...] = ()
    knowledge: dict[str, Any] = field(default_factory=dict)


def build_repair_context(job: RepairJob, diagnosis: RepairDiagnosis, *, knowledge: ArchiveKnowledge | None = None) -> RepairContext:
    knowledge = knowledge if isinstance(knowledge, ArchiveKnowledge) else ArchiveKnowledge.from_any(job.knowledge)
    failure = knowledge_view.extraction_failure(knowledge)
    diagnostics = knowledge_view.extraction_diagnostics(knowledge)
    result_payload = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    native_diagnostics = result_payload.get("diagnostics") if isinstance(result_payload.get("diagnostics"), dict) else {}
    fuzzy_profile = knowledge_view.inspection_fuzzy_profile(knowledge)
    failure_stage = _first_text([
        failure.get("failure_stage"),
        result_payload.get("failure_stage"),
        native_diagnostics.get("failure_stage"),
        diagnostics.get("failure_stage"),
    ])
    failure_kind = _first_text([
        failure.get("failure_kind"),
        result_payload.get("failure_kind"),
        native_diagnostics.get("failure_kind"),
        diagnostics.get("failure_kind"),
    ])
    route_context = knowledge_view.repair_route_context(knowledge)
    history_summary = knowledge_view.repair_history_summary(knowledge)
    route_evidence_flags = list(route_context.get("route_evidence_flags") or [])
    repair_history_flags = list(history_summary.get("repair_history_flags") or [])
    residual_damage_flags = list(route_context.get("residual_damage_flags") or history_summary.get("residual_damage_flags") or [])
    context_format = _normalize_format(diagnosis.format or knowledge_view.inspection_summary(knowledge).get("format") or "")
    damage_flags = _dedupe([
        *list(route_context.get("damage_flags") or []),
        *[str(flag) for flag in getattr(job, "damage_flags", []) or [] if str(flag)],
        *[flag for item in diagnosis.evidence for flag in item.damage_flags],
        *_failure_damage_flags(job, failure, failure_kind, failure_stage),
        *route_evidence_flags,
        *repair_history_flags,
        *residual_damage_flags,
    ])
    if context_format == "zip":
        damage_flags = _normalize_zip_generic_damage(damage_flags)
    elif context_format in {"7z", "seven_zip"}:
        damage_flags = _filter_seven_zip_conflicting_runtime_flags(damage_flags, {"archive_knowledge": knowledge.to_dict()})
    knowledge_payload = knowledge.to_dict()
    if _normalize_format(diagnosis.format or knowledge_view.inspection_summary(knowledge).get("format") or "") == "zip":
        damage_flags = _filter_zip_conflicting_runtime_flags(damage_flags, {
            "archive_knowledge": knowledge_payload,
            "inspection_evidence": {"details": knowledge_view.zip_runtime_facts(knowledge)},
            "repair_history": history_summary,
            "damage_flags": damage_flags,
        })
    failure_kind = _archive_scoped_failure_kind(failure_kind, damage_flags)
    authentication = knowledge_view.archive_authentication(knowledge)
    normalized_failure_classes = _normalized_failure_classes(
        failure_kind,
        damage_flags,
        authentication=authentication,
        fmt=context_format,
    )
    damage_flags = _dedupe([*damage_flags, *normalized_failure_classes])
    source = knowledge_view.source_input(knowledge)
    inspection_summary = knowledge_view.inspection_summary(knowledge)
    prepass = knowledge_view.inspection_prepass(knowledge)
    return RepairContext(
        source_input=dict(source),
        format=_normalize_format(diagnosis.format or inspection_summary.get("format") or source.get("format_hint") or source.get("format") or ""),
        confidence=float(diagnosis.confidence or inspection_summary.get("confidence") or 0.0),
        categories=tuple(str(item) for item in diagnosis.categories),
        damage_flags=tuple(damage_flags),
        fuzzy_hints=tuple(str(item) for item in fuzzy_profile.get("hints") or []),
        offset_hints=tuple(
            dict(item)
            for item in fuzzy_profile.get("offset_hints") or []
            if isinstance(item, dict)
        ),
        failure_stage=str(failure_stage),
        failure_kind=str(failure_kind),
        failure_status=_first_text([failure.get("status"), result_payload.get("status")]),
        native_status=_first_text([failure.get("native_status"), result_payload.get("native_status")]),
        operation_result_name=_first_text([
            failure.get("operation_result_name"),
            result_payload.get("operation_result_name"),
            native_diagnostics.get("operation_result_name"),
        ]),
        failed_item=_first_text([failure.get("failed_item"), result_payload.get("failed_item")]),
        structure_evidence=None,
        archive_coverage=coverage_view_from_payload(_archive_coverage(failure), _file_observations(failure)),
        prepass=dict(prepass),
        fuzzy_profile=fuzzy_profile,
        extraction_failure=failure,
        extraction_diagnostics=diagnostics,
        route_evidence_flags=tuple(route_evidence_flags),
        repair_history_flags=tuple(repair_history_flags),
        residual_damage_flags=tuple(residual_damage_flags),
        knowledge=knowledge_payload,
    )


def _archive_scoped_failure_kind(failure_kind: str, damage_flags: list[str]) -> str:
    if str(failure_kind or "") != "output_filesystem":
        return str(failure_kind or "")
    evidence_flags = set(damage_flags or []) & {
        "data_descriptor",
        "central_directory_bad",
        "central_directory_offset_bad",
        "central_directory_count_bad",
        "compressed_size_bad",
        "checksum_error",
        "crc_error",
        "damaged",
        "content_integrity_bad_or_unknown",
        "local_header_recovery",
        "local_header_conflict",
        "payload_hash_mismatch",
    }
    return "corrupted_data" if evidence_flags else "output_filesystem"


def _normalized_failure_classes(
    failure_kind: str,
    damage_flags: list[str],
    *,
    authentication: dict[str, Any],
    fmt: str,
) -> list[str]:
    if _normalize_format(fmt) not in {"7z", "seven_zip"}:
        return []
    if str(failure_kind or "").lower() not in {"encrypted_or_wrong_password", "wrong_password"}:
        return []
    if bool(authentication.get("authentication_blocking")):
        return []
    flags = {str(flag) for flag in damage_flags if str(flag)}
    structural = {
        "seven_zip_signature_found",
        "split_sidecars_available",
        "split_archive",
        "carrier_prefix",
        "carrier_archive",
        "embedded_archive",
        "trailing_junk",
        "next_header_out_of_range",
        "next_header_offset_bad",
        "next_header_size_bad",
        "start_header_crc_bad",
        "next_header_crc_bad",
        "pack_stream_offset_bad",
        "pack_stream_size_bad",
        "stream_crc_bad",
        "substream_crc_bad",
        "packed_stream_bad",
        "payload_crc_bad",
        "partial_recovery_possible",
    }
    return ["structure_recognition", "corrupted_data"] if flags & structural else []


def runtime_route_evidence_flags(payload: dict[str, Any]) -> list[str]:
    fmt = _format_from_payload(payload)
    if fmt in {"7z", "seven_zip"}:
        return seven_zip_route_evidence_flags(payload)
    if fmt == "zip" or not fmt:
        return zip_route_evidence_flags(payload)
    return _dedupe([str(item) for item in payload.get("damage_flags") or [] if str(item)])


















































def _failure_damage_flags(
    job: RepairJob,
    failure: dict[str, Any],
    failure_kind: str,
    failure_stage: str,
) -> list[str]:
    flags = []
    if failure.get("checksum_error"):
        flags.append("checksum_error")
    if failure.get("missing_volume"):
        flags.append("missing_volume")
    if failure.get("wrong_password") and not _has_resolved_password(job):
        flags.append("wrong_password")
    if failure.get("unsupported_method"):
        flags.append("unsupported_method")
    if failure.get("partial_outputs"):
        flags.append("partial_extract_available")
    coverage = _archive_coverage(failure)
    flags.extend(_coverage_flags(coverage))
    if failure_kind:
        flags.append(failure_kind)
    if failure_stage == "archive_open" and failure_kind == "structure_recognition":
        flags.extend(["structure_recognition", "directory_integrity_bad_or_unknown"])
    if failure_kind in {"corrupted_data", "data_error"}:
        flags.extend(["damaged", "data_error"])
    if failure_kind in {"unexpected_end", "input_truncated", "stream_truncated"}:
        flags.extend(["unexpected_end", "input_truncated"])
    if failure_kind == "output_filesystem":
        flags.append("output_filesystem")
    if failure_stage.startswith("worker_") or failure_kind.startswith("process_"):
        flags.append("process_failure")
    if _has_resolved_password(job):
        flags = [flag for flag in flags if str(flag) != "wrong_password"]
    return _dedupe([str(item) for item in flags if item])


def _has_resolved_password(job: RepairJob) -> bool:
    return job.password is not None and str(job.password) != ""


def _archive_coverage(failure: dict[str, Any]) -> dict[str, Any]:
    coverage = failure.get("archive_coverage")
    return dict(coverage) if isinstance(coverage, dict) else {}


def _file_observations(failure: dict[str, Any]) -> list[Any]:
    observations = failure.get("file_observations")
    return list(observations) if isinstance(observations, list) else []


def _coverage_flags(coverage: dict[str, Any]) -> list[str]:
    if not coverage:
        return []
    flags: list[str] = []
    completeness = float(coverage.get("completeness", 0.0) or 0.0)
    expected = int(coverage.get("expected_files", 0) or 0)
    matched = int(coverage.get("matched_files", 0) or 0)
    failed = int(coverage.get("failed_files", 0) or 0)
    partial = int(coverage.get("partial_files", 0) or 0)
    missing = int(coverage.get("missing_files", 0) or 0)
    if completeness < 1.0:
        flags.append("partial_extract_available")
    if (expected and matched < expected) or missing:
        flags.append("missing_entries")
    if failed or partial:
        flags.append("content_integrity_bad_or_unknown")
    return flags


def _first_text(values: list[Any]) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _dedupe(values: list[Any]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output
