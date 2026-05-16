from __future__ import annotations

from dataclasses import asdict
from contextlib import nullcontext
from typing import Any

from sunpack.contracts.tasks import ArchiveTask
from sunpack.verification.result import VerificationResult
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_flags, write_payload


def write_verification_result(
    task: ArchiveTask,
    result: VerificationResult,
    *,
    phase_timer: Any | None = None,
    phase_prefix: str = "write_verification",
) -> None:
    with _phase(phase_timer, f"{phase_prefix}_ensure_knowledge"):
        knowledge = ensure_knowledge(task)
    with _phase(phase_timer, f"{phase_prefix}_build_summary"):
        output_quality = {
            "score": float(result.output_quality_score),
            "file_count": int(result.output_file_count),
            "total_bytes": int(result.output_total_bytes),
            "complete_ratio": float(result.output_complete_ratio),
            "failed_ratio": float(result.output_failed_ratio),
            "empty": bool(result.output_empty),
            "confidence": float(result.output_confidence),
        }
        summary = {
            "methods_run": list(result.methods_run),
            "completeness": float(result.completeness),
            "recoverable_upper_bound": float(result.recoverable_upper_bound),
            "assessment_status": result.assessment_status,
            "source_integrity": result.source_integrity,
            "decision_hint": result.decision_hint,
            "complete_files": int(result.complete_files),
            "partial_files": int(result.partial_files),
            "failed_files": int(result.failed_files),
            "missing_files": int(result.missing_files),
            "unverified_files": int(result.unverified_files),
            "output_quality_score": output_quality["score"],
            "output_file_count": output_quality["file_count"],
            "output_total_bytes": output_quality["total_bytes"],
            "output_complete_ratio": output_quality["complete_ratio"],
            "output_failed_ratio": output_quality["failed_ratio"],
            "output_empty": output_quality["empty"],
            "output_confidence": output_quality["confidence"],
            "output_quality": output_quality,
            "archive_coverage": asdict(result.archive_coverage),
            "coverage_breakdown": _coverage_breakdown(result),
            "repair_hints": dict(result.repair_hints or {}),
        }
    with _phase(phase_timer, f"{phase_prefix}_write_summary"):
        write_payload(knowledge, "verification.summary", summary, source_layer="verification", source_module="scheduler")
        write_payload(knowledge, "verification", {"coverage_breakdown": summary["coverage_breakdown"]}, source_layer="verification", source_module="scheduler")
    with _phase(phase_timer, f"{phase_prefix}_write_observations"):
        write_payload(
            knowledge,
            "verification",
            {
                "issues": [asdict(item) for item in result.issues],
                "file_observations": [asdict(item) for item in result.file_observations],
            },
            source_layer="verification",
            source_module="scheduler",
        )
    with _phase(phase_timer, f"{phase_prefix}_residual_flags"):
        residual = _residual_flags(result)
    if residual:
        with _phase(phase_timer, f"{phase_prefix}_write_residual_flags"):
            write_flags(knowledge, "verification.residual", residual, source_layer="verification", source_module="scheduler")
            write_flags(knowledge, "repair.residual", residual, source_layer="verification", source_module="scheduler")
    with _phase(phase_timer, f"{phase_prefix}_commit"):
        commit_task_knowledge(task, knowledge, phase_timer=phase_timer, phase_prefix=f"{phase_prefix}_commit")
    with _phase(phase_timer, f"{phase_prefix}_zip_runtime_evidence"):
        try:
            from sunpack.analysis.knowledge import write_zip_runtime_evidence_facts

            write_zip_runtime_evidence_facts(task)
        except Exception:
            pass


def _residual_flags(result: VerificationResult) -> list[str]:
    flags: list[str] = []
    if result.completeness < 1.0:
        flags.append("partial_entries_remaining")
    if result.failed_files or result.partial_files:
        flags.append("content_integrity_bad_or_unknown")
    if result.missing_files:
        flags.append("missing_entries")
    for issue in result.issues:
        text = f"{issue.code} {issue.message}".lower()
        if "crc" in text or "checksum" in text:
            flags.extend(["checksum_error", "crc_error", "payload_hash_mismatch"])
    return _dedupe(flags)


def _coverage_breakdown(result: VerificationResult) -> dict[str, Any]:
    coverage = result.archive_coverage
    expected_files = int(coverage.expected_files or result.output_file_count or 0)
    complete_files = int(coverage.complete_files or result.complete_files or 0)
    partial_files = int(coverage.partial_files or result.partial_files or 0)
    failed_files = int(coverage.failed_files or result.failed_files or 0)
    missing_files = int(coverage.missing_files or result.missing_files or 0)
    unverified_files = int(coverage.unverified_files or result.unverified_files or 0)
    observed_total = expected_files or complete_files + partial_files + failed_files + missing_files + unverified_files
    issue_counts = _issue_counts(result)
    observation_counts = _observation_counts(result)
    crc_mismatch = max(issue_counts["crc_mismatch_count"], observation_counts["crc_mismatch_count"])
    size_mismatch = max(issue_counts["size_mismatch_count"], observation_counts["size_mismatch_count"])
    output_missing = max(issue_counts["output_missing_count"], missing_files)
    coverage_confident = float(coverage.confidence or 0.0) > 0.0
    completeness = float(coverage.completeness if coverage_confident else result.completeness or 0.0)
    file_coverage = float(coverage.file_coverage if coverage_confident else 0.0)
    byte_coverage = float(coverage.byte_coverage if coverage_confident else 0.0)
    return {
        "expected_files": expected_files,
        "matched_files": int(coverage.matched_files or 0),
        "complete_files": complete_files,
        "partial_files": partial_files,
        "failed_files": failed_files,
        "missing_files": missing_files,
        "unverified_files": unverified_files,
        "complete_ratio": _ratio(complete_files, observed_total),
        "partial_ratio": _ratio(partial_files, observed_total),
        "failed_ratio": _ratio(failed_files, observed_total),
        "missing_ratio": _ratio(missing_files, observed_total),
        "unverified_ratio": _ratio(unverified_files, observed_total),
        "expected_bytes": int(coverage.expected_bytes or 0),
        "matched_bytes": int(coverage.matched_bytes or 0),
        "complete_bytes": int(coverage.complete_bytes or 0),
        "file_coverage": file_coverage,
        "byte_coverage": byte_coverage,
        "completeness": completeness,
        "coverage_confidence": float(coverage.confidence or 0.0),
        "crc_mismatch_count": crc_mismatch,
        "size_mismatch_count": size_mismatch,
        "output_missing_count": output_missing,
        "payload_hash_mismatch_count": issue_counts["payload_hash_mismatch_count"],
        "archive_crc_file_missing_count": issue_counts["archive_crc_file_missing_count"],
        "archive_crc_test_failed_count": issue_counts["archive_crc_test_failed_count"],
    }


def _issue_counts(result: VerificationResult) -> dict[str, int]:
    counts = {
        "crc_mismatch_count": 0,
        "size_mismatch_count": 0,
        "output_missing_count": 0,
        "payload_hash_mismatch_count": 0,
        "archive_crc_file_missing_count": 0,
        "archive_crc_test_failed_count": 0,
    }
    for issue in result.issues:
        code = str(issue.code or "").lower()
        message = str(issue.message or "").lower()
        text = f"{code} {message}"
        if "crc" in text or "checksum" in text:
            counts["crc_mismatch_count"] += 1
        if "size" in text or "length" in text:
            counts["size_mismatch_count"] += 1
        if "missing" in text or "output_missing" in text:
            counts["output_missing_count"] += 1
        if "payload_hash" in text or "hash_mismatch" in text:
            counts["payload_hash_mismatch_count"] += 1
        if "archive_crc_file_missing" in code:
            counts["archive_crc_file_missing_count"] += 1
        if "archive_crc_test_failed" in code:
            counts["archive_crc_test_failed_count"] += 1
    return counts


def _observation_counts(result: VerificationResult) -> dict[str, int]:
    counts = {"crc_mismatch_count": 0, "size_mismatch_count": 0}
    for item in result.file_observations:
        if item.crc_expected is not None and item.crc_actual is not None and item.crc_expected != item.crc_actual:
            counts["crc_mismatch_count"] += 1
        if item.expected_size is not None and item.bytes_written and int(item.bytes_written) != int(item.expected_size):
            counts["size_mismatch_count"] += 1
        for issue in item.issues:
            text = f"{issue.code} {issue.message}".lower()
            if "crc" in text or "checksum" in text:
                counts["crc_mismatch_count"] += 1
            if "size" in text or "length" in text:
                counts["size_mismatch_count"] += 1
    return counts


def _ratio(value: int, total: int) -> float:
    return float(value) / float(max(1, int(total or 0)))


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _phase(timer: Any | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
