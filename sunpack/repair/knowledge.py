from __future__ import annotations

from dataclasses import asdict
from typing import Any

from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.result import ExtractionResult
from sunpack.repair.context import normalize_zip_runtime_route_evidence
from sunpack.repair.result import RepairResult
from sunpack.support.archive_knowledge_writer import (
    append_history,
    commit_task_knowledge,
    ensure_knowledge,
    write_flags,
    write_payload,
)
from sunpack.verification.result import VerificationResult


def write_repair_job_context(
    task: ArchiveTask,
    *,
    source_input: dict[str, Any],
    analysis_prepass: dict[str, Any],
    analysis_evidence: Any,
    extraction_failure: dict[str, Any],
    extraction_diagnostics: dict[str, Any],
    repair_history: dict[str, Any],
    route_payload: dict[str, Any],
    verification: VerificationResult,
) -> dict[str, Any]:
    knowledge = ensure_knowledge(task)
    evidence_payload = _analysis_evidence_payload(analysis_evidence)
    write_payload(knowledge, "source.input", dict(source_input or {}), source_layer="repair", source_module="job_context")
    write_payload(knowledge, "analysis.prepass", dict(analysis_prepass or {}), source_layer="repair", source_module="job_context")
    if evidence_payload:
        write_payload(knowledge, "analysis.evidence", evidence_payload, source_layer="repair", source_module="job_context")
    write_payload(knowledge, "extraction.failure", dict(extraction_failure or {}), source_layer="repair", source_module="job_context")
    write_payload(knowledge, "extraction.diagnostics", dict(extraction_diagnostics or {}), source_layer="repair", source_module="job_context")
    write_payload(knowledge, "repair.history", dict(repair_history or {}), source_layer="repair", source_module="job_context")
    write_payload(knowledge, "verification.summary", _verification_payload(verification), source_layer="repair", source_module="job_context")

    normalized = normalize_zip_runtime_route_evidence({
        "source_input": source_input,
        "analysis_prepass": analysis_prepass,
        "analysis_evidence": evidence_payload,
        "extraction_failure": extraction_failure,
        "extraction_diagnostics": extraction_diagnostics,
        "repair_history": repair_history,
        "archive_knowledge": knowledge.to_dict(),
        "damage_flags": list(route_payload.get("damage_flags") or []),
    })
    route_flags = [str(flag) for flag in normalized.get("route_evidence_flags") or route_payload.get("route_evidence_flags") or [] if str(flag)]
    damage_flags = [str(flag) for flag in normalized.get("damage_flags") or route_payload.get("damage_flags") or [] if str(flag)]
    if route_flags:
        write_flags(knowledge, "repair.route_evidence", route_flags, source_layer="repair", source_module="job_context")
        write_payload(knowledge, "format.zip", {"route_evidence_flags": route_flags}, source_layer="repair", source_module="job_context")
    if damage_flags:
        write_flags(knowledge, "repair.damage", damage_flags, source_layer="repair", source_module="job_context")
    source_derivation = normalized.get("source_derivation") if isinstance(normalized.get("source_derivation"), dict) else {}
    if source_derivation:
        write_payload(knowledge, "source.derivation", source_derivation, source_layer="repair", source_module="job_context")
    commit_task_knowledge(task, knowledge)
    return knowledge.to_dict()


def write_repair_result(task: ArchiveTask, result: RepairResult, *, phase: str = "repair") -> None:
    knowledge = ensure_knowledge(task)
    payload = _repair_result_payload(result)
    append_history(knowledge, "repair.history.items", payload, source_layer="repair", source_module=result.module_name)
    write_payload(knowledge, "repair.last_result", payload, source_layer="repair", source_module=result.module_name)
    history_payload = knowledge.get("repair.history")
    history_payload = dict(history_payload) if isinstance(history_payload, dict) else {}
    if result.actions:
        write_payload(
            knowledge,
            "repair.history",
            {"previous_actions": _dedupe([*list(history_payload.get("previous_actions") or []), *list(result.actions)])},
            source_layer="repair",
            source_module=result.module_name,
        )
    if result.module_name:
        write_payload(
            knowledge,
            "repair.history",
            {"previous_modules": _dedupe([*list(history_payload.get("previous_modules") or []), result.module_name])},
            source_layer="repair",
            source_module=result.module_name,
        )
        write_flags(knowledge, "repair.history", [f"already_tried:{result.module_name}"], source_layer="repair", source_module=result.module_name)
    diagnosis = result.diagnosis if isinstance(result.diagnosis, dict) else {}
    for key, namespace in (("patch_facts", "repair.patch_facts"), ("residual_facts", "repair.residual")):
        values = diagnosis.get(key)
        if isinstance(values, list):
            write_flags(knowledge, namespace, [str(item) for item in values], source_layer="repair", source_module=result.module_name)
    write_payload(knowledge, "repair", {"status": result.status, "phase": phase}, source_layer="repair", source_module=result.module_name)
    commit_task_knowledge(task, knowledge)


def write_repair_stop(task: ArchiveTask, reason: str, payload: dict[str, Any] | None = None) -> None:
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "repair.stop",
        {"reason": str(reason or ""), "details": dict(payload or {})},
        source_layer="repair",
        source_module="loop",
    )
    commit_task_knowledge(task, knowledge)


def write_repair_attempt(task: ArchiveTask, attempts: int, *, trigger: str = "") -> None:
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "repair",
        {"attempts": int(attempts or 0), "last_trigger": str(trigger or "")},
        source_layer="repair",
        source_module="stage",
    )
    commit_task_knowledge(task, knowledge)


def write_repair_loop_state(task: ArchiveTask, payload: dict[str, Any]) -> None:
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "repair.loop",
        dict(payload or {}),
        source_layer="repair",
        source_module="loop",
    )
    commit_task_knowledge(task, knowledge)


def _analysis_evidence_payload(evidence: Any) -> dict[str, Any]:
    if evidence is None:
        return {}
    details = getattr(evidence, "details", None)
    return {
        "format": str(getattr(evidence, "format", "") or getattr(evidence, "archive_type", "") or ""),
        "confidence": float(getattr(evidence, "confidence", 0.0) or 0.0),
        "status": str(getattr(evidence, "status", "") or ""),
        "details": dict(details) if isinstance(details, dict) else {},
    }


def _verification_payload(verification: VerificationResult) -> dict[str, Any]:
    return {
        "completeness": verification.completeness,
        "recoverable_upper_bound": verification.recoverable_upper_bound,
        "assessment_status": verification.assessment_status,
        "source_integrity": verification.source_integrity,
        "decision_hint": verification.decision_hint,
        "complete_files": verification.complete_files,
        "partial_files": verification.partial_files,
        "failed_files": verification.failed_files,
        "missing_files": verification.missing_files,
        "unverified_files": verification.unverified_files,
        "archive_coverage": asdict(verification.archive_coverage),
        "repair_hints": dict(verification.repair_hints or {}),
    }


def _repair_result_payload(result: RepairResult) -> dict[str, Any]:
    return {
        "ok": bool(result.ok),
        "status": result.status,
        "module_name": result.module_name,
        "actions": list(result.actions or []),
        "diagnosis": dict(result.diagnosis or {}),
        "repaired_input": dict(result.repaired_input or {}),
    }


def _dedupe(values: list[Any]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output
