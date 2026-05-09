from __future__ import annotations

from dataclasses import asdict
from typing import Any

from sunpack.contracts.tasks import ArchiveTask
from sunpack.verification.result import VerificationResult
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_flags, write_payload


def write_verification_result(task: ArchiveTask, result: VerificationResult) -> None:
    knowledge = ensure_knowledge(task)
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
        "archive_coverage": asdict(result.archive_coverage),
        "repair_hints": dict(result.repair_hints or {}),
    }
    write_payload(knowledge, "verification.summary", summary, source_layer="verification", source_module="scheduler")
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
    residual = _residual_flags(result)
    if residual:
        write_flags(knowledge, "verification.residual", residual, source_layer="verification", source_module="scheduler")
        write_flags(knowledge, "repair.residual", residual, source_layer="verification", source_module="scheduler")
    commit_task_knowledge(task, knowledge)


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


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
