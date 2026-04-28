from dataclasses import dataclass, field
from typing import Any

from smart_unpacker.repair.job import RepairJob


BOUNDARY_FLAGS = {
    "boundary_unreliable",
    "start_trusted_only",
    "missing_end_block",
    "probably_truncated",
    "stream_truncated",
    "input_truncated",
    "truncated",
    "unexpected_end",
    "unexpected_eof",
    "start_header_corrupt",
    "trailing_junk",
    "central_directory_offset_bad",
    "comment_length_bad",
    "compressed_size_bad",
}
DIRECTORY_FLAGS = {
    "eocd_bad",
    "central_directory_bad",
    "central_directory_offset_bad",
    "central_directory_count_bad",
    "directory_integrity_bad_or_unknown",
    "local_header_recovery",
    "local_headers_present",
    "start_header_crc_bad",
    "start_header_corrupt",
    "tar_checksum_bad",
    "data_descriptor",
}
CONTENT_FLAGS = {
    "damaged",
    "content_integrity_bad_or_unknown",
    "checksum_error",
    "crc_error",
    "gzip_footer_bad",
    "local_header_recovery",
    "stream_truncated",
    "input_truncated",
    "truncated",
    "unexpected_end",
    "unexpected_eof",
    "data_error",
}


@dataclass(frozen=True)
class DamageEvidence:
    source: str
    format: str = ""
    confidence: float = 0.0
    start_trusted: bool = False
    end_trusted: bool = False
    damage_flags: list[str] = field(default_factory=list)
    worker_status: str = ""
    operation_result: int | None = None
    failed_item: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RepairDiagnosis:
    format: str
    categories: list[str] = field(default_factory=list)
    severity: str = "unknown"
    confidence: float = 0.0
    start_trusted: bool = False
    end_trusted: bool = False
    repairable: bool = True
    unsafe_actions: list[str] = field(default_factory=list)
    evidence: list[DamageEvidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "categories": list(self.categories),
            "severity": self.severity,
            "confidence": self.confidence,
            "start_trusted": self.start_trusted,
            "end_trusted": self.end_trusted,
            "repairable": self.repairable,
            "unsafe_actions": list(self.unsafe_actions),
            "notes": list(self.notes),
        }


def diagnose_repair_job(job: RepairJob) -> RepairDiagnosis:
    evidences = _collect_evidence(job)
    fmt = _first_text([job.format, *(item.format for item in evidences)])
    flags = {flag for item in evidences for flag in item.damage_flags}
    categories = _categories_for(fmt, flags, job.extraction_failure or {})
    severity = _severity(flags, job.extraction_failure or {}, job.confidence)
    repairable, unsafe_actions, notes = _repairability(job, flags)
    return RepairDiagnosis(
        format=fmt,
        categories=categories,
        severity=severity,
        confidence=max([job.confidence, *(item.confidence for item in evidences)] or [0.0]),
        start_trusted=any(item.start_trusted for item in evidences) or "start_trusted_only" in flags,
        end_trusted=any(item.end_trusted for item in evidences) and "boundary_unreliable" not in flags,
        repairable=repairable,
        unsafe_actions=unsafe_actions,
        evidence=evidences,
        notes=notes,
    )


def _collect_evidence(job: RepairJob) -> list[DamageEvidence]:
    evidences: list[DamageEvidence] = []
    if job.analysis_evidence is not None:
        evidences.append(_analysis_evidence(job))
    if job.extraction_failure:
        evidences.append(_extraction_evidence(job))
    if job.damage_flags and not evidences:
        evidences.append(DamageEvidence(
            source="job",
            format=job.format,
            confidence=job.confidence,
            damage_flags=list(job.damage_flags),
        ))
    return evidences


def _analysis_evidence(job: RepairJob) -> DamageEvidence:
    evidence = job.analysis_evidence
    segments = list(getattr(evidence, "segments", None) or [])
    flags = list(job.damage_flags)
    start_trusted = False
    end_trusted = False
    if segments:
        primary = segments[0]
        flags.extend(list(getattr(primary, "damage_flags", None) or []))
        start_trusted = getattr(primary, "start_offset", None) is not None
        end_trusted = getattr(primary, "end_offset", None) is not None and "boundary_unreliable" not in flags
    return DamageEvidence(
        source="analysis",
        format=str(getattr(evidence, "format", "") or job.format),
        confidence=float(getattr(evidence, "confidence", job.confidence) or 0.0),
        start_trusted=start_trusted,
        end_trusted=end_trusted,
        damage_flags=_dedupe(flags),
        details={"status": getattr(evidence, "status", "")},
    )


def _extraction_evidence(job: RepairJob) -> DamageEvidence:
    failure = dict(job.extraction_failure or {})
    flags = list(job.damage_flags)
    if failure.get("checksum_error"):
        flags.append("checksum_error")
    if failure.get("missing_volume"):
        flags.append("missing_volume")
    if failure.get("damaged"):
        flags.append("damaged")
    if failure.get("wrong_password"):
        flags.append("wrong_password")
    return DamageEvidence(
        source="extraction",
        format=str(failure.get("archive_type") or failure.get("format") or job.format or ""),
        confidence=job.confidence,
        damage_flags=_dedupe(flags),
        worker_status=str(failure.get("native_status") or failure.get("status") or ""),
        operation_result=failure.get("operation_result"),
        failed_item=str(failure.get("failed_item") or ""),
        details=failure,
    )


def _categories_for(fmt: str, flags: set[str], failure: dict[str, Any]) -> list[str]:
    categories: list[str] = []
    if flags & BOUNDARY_FLAGS or failure.get("missing_volume"):
        categories.append("boundary_repair")
    if flags & DIRECTORY_FLAGS:
        categories.append("directory_rebuild")
    if flags & CONTENT_FLAGS or failure.get("failed_item"):
        categories.append("content_recovery")
    if failure.get("unsupported_method"):
        categories.append("unsupported_method")
    if not categories:
        categories.append("safe_repair")
    if fmt.lower() == "zip" and "local_header_recovery" in flags and "directory_rebuild" not in categories:
        categories.append("directory_rebuild")
    return _dedupe(categories)


def _severity(flags: set[str], failure: dict[str, Any], confidence: float) -> str:
    if "wrong_password" in flags or failure.get("wrong_password"):
        return "blocked"
    if "missing_volume" in flags or failure.get("missing_volume"):
        return "high"
    if "damaged" in flags or failure.get("damaged"):
        return "high"
    if confidence and confidence < 0.5:
        return "medium"
    if flags:
        return "medium"
    return "low"


def _repairability(job: RepairJob, flags: set[str]) -> tuple[bool, list[str], list[str]]:
    if "wrong_password" in flags:
        return False, [], ["password must be resolved before structural repair"]
    unsafe: list[str] = []
    if "missing_volume" in flags:
        unsafe.append("volume_synthesis")
    if job.attempts >= 2:
        return False, unsafe, ["repair attempt limit reached"]
    return True, unsafe, []


def _first_text(values) -> str:
    for value in values:
        text = str(value or "").strip().lower()
        if text:
            return text.lstrip(".")
    return "unknown"


def _dedupe(values) -> list:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
