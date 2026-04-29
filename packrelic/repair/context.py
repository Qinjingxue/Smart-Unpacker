from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from packrelic.repair.coverage import ArchiveCoverageView, coverage_view_from_payload
from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob


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


def build_repair_context(job: RepairJob, diagnosis: RepairDiagnosis) -> RepairContext:
    failure = dict(job.extraction_failure or {})
    diagnostics = _diagnostics_from(job, failure)
    result_payload = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    native_diagnostics = result_payload.get("diagnostics") if isinstance(result_payload.get("diagnostics"), dict) else {}
    fuzzy_profile = _fuzzy_profile(job)
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
    return RepairContext(
        source_input=dict(job.source_input or {}),
        format=_normalize_format(diagnosis.format or job.format),
        confidence=float(diagnosis.confidence or job.confidence or 0.0),
        categories=tuple(str(item) for item in diagnosis.categories),
        damage_flags=tuple(_damage_flags(job, diagnosis, failure, failure_kind, failure_stage)),
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
        structure_evidence=job.analysis_evidence,
        archive_coverage=coverage_view_from_payload(_archive_coverage(failure), _file_observations(failure)),
        prepass=dict(job.analysis_prepass or {}),
        fuzzy_profile=fuzzy_profile,
        extraction_failure=failure,
        extraction_diagnostics=diagnostics,
    )


def _diagnostics_from(job: RepairJob, failure: dict[str, Any]) -> dict[str, Any]:
    if isinstance(job.extraction_diagnostics, dict) and job.extraction_diagnostics:
        return dict(job.extraction_diagnostics)
    diagnostics = failure.get("diagnostics")
    return dict(diagnostics) if isinstance(diagnostics, dict) else {}


def _fuzzy_profile(job: RepairJob) -> dict[str, Any]:
    if isinstance(job.fuzzy_profile, dict) and job.fuzzy_profile:
        return dict(job.fuzzy_profile)
    fuzzy = job.analysis_prepass.get("fuzzy") if isinstance(job.analysis_prepass, dict) else {}
    if isinstance(fuzzy, dict) and isinstance(fuzzy.get("binary_profile"), dict):
        return dict(fuzzy["binary_profile"])
    evidence = job.analysis_evidence
    details = getattr(evidence, "details", {}) if evidence is not None else {}
    route = details.get("fuzzy") if isinstance(details, dict) else {}
    profile = route.get("profile") if isinstance(route, dict) else {}
    return dict(profile) if isinstance(profile, dict) else {}


def _damage_flags(
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    failure: dict[str, Any],
    failure_kind: str,
    failure_stage: str,
) -> list[str]:
    flags = []
    flags.extend(job.damage_flags)
    for evidence in diagnosis.evidence:
        flags.extend(evidence.damage_flags)
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


def _normalize_format(value: str) -> str:
    text = str(value or "").lower().lstrip(".")
    aliases = {"seven_zip": "7z", "sevenzip": "7z", "gz": "gzip", "bz2": "bzip2", "zst": "zstd"}
    return aliases.get(text, text or "unknown")


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
