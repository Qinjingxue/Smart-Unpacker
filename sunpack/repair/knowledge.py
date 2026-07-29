from __future__ import annotations

from contextlib import nullcontext
from dataclasses import asdict
from typing import Any, Callable

from sunpack.contracts.tasks import ArchiveTask
from sunpack.support.runtime_route_evidence import normalize_runtime_route_evidence
from sunpack.repair.result import RepairResult
from sunpack.support.archive_knowledge_writer import (
    append_history,
    commit_task_knowledge,
    ensure_knowledge,
    write_flags,
    write_payload,
    write_value,
)
from sunpack.contracts.verification import VerificationResult


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
    phase_timer: Callable[..., Any] | None = None,
    phase_prefix: str = "write_repair_job_context",
) -> dict[str, Any]:
    with _phase(phase_timer, f"{phase_prefix}_ensure_knowledge"):
        knowledge = ensure_knowledge(task)
    with _phase(phase_timer, f"{phase_prefix}_analysis_evidence_payload"):
        evidence_payload = _analysis_evidence_payload(analysis_evidence)
    with _phase(phase_timer, f"{phase_prefix}_write_source_input"):
        write_payload(knowledge, "source.input", dict(source_input or {}), source_layer="repair", source_module="job_context")
    with _phase(phase_timer, f"{phase_prefix}_write_analysis_prepass"):
        write_payload(knowledge, "analysis.prepass", dict(analysis_prepass or {}), source_layer="repair", source_module="job_context")
    with _phase(phase_timer, f"{phase_prefix}_write_analysis_evidence"):
        if evidence_payload:
            write_payload(knowledge, "analysis.evidence", evidence_payload, source_layer="repair", source_module="job_context")
    with _phase(phase_timer, f"{phase_prefix}_write_extraction_failure"):
        write_payload(knowledge, "extraction.failure", dict(extraction_failure or {}), source_layer="repair", source_module="job_context")
    with _phase(phase_timer, f"{phase_prefix}_write_extraction_diagnostics"):
        write_payload(knowledge, "extraction.diagnostics", dict(extraction_diagnostics or {}), source_layer="repair", source_module="job_context")
    with _phase(phase_timer, f"{phase_prefix}_write_repair_history"):
        write_value(knowledge, "repair.history", dict(repair_history or {}), source_layer="repair", source_module="job_context")
    with _phase(phase_timer, f"{phase_prefix}_write_verification_summary"):
        write_payload(knowledge, "verification.summary", _verification_payload(verification), source_layer="repair", source_module="job_context")
    with _phase(phase_timer, f"{phase_prefix}_write_analysis_summary"):
        if route_payload.get("format"):
            write_payload(
                knowledge,
                "analysis.summary",
                {"format": str(route_payload.get("format") or ""), "confidence": getattr(verification, "confidence", None)},
                source_layer="repair",
                source_module="job_context",
            )

    with _phase(phase_timer, f"{phase_prefix}_normalize_route_evidence"):
        route_flags = [str(flag) for flag in route_payload.get("route_evidence_flags") or [] if str(flag)]
        damage_flags = [str(flag) for flag in route_payload.get("damage_flags") or [] if str(flag)]
        if not route_flags and not damage_flags:
            normalized = normalize_runtime_route_evidence({
                **dict(route_payload or {}),
                "source_input": source_input,
                "analysis_prepass": analysis_prepass,
                "analysis_evidence": evidence_payload,
                "extraction_failure": extraction_failure,
                "extraction_diagnostics": extraction_diagnostics,
                "repair_history": repair_history,
                "damage_flags": [],
            })
            route_flags = [str(flag) for flag in normalized.get("route_evidence_flags") or [] if str(flag)]
            damage_flags = [str(flag) for flag in normalized.get("damage_flags") or [] if str(flag)]
    with _phase(phase_timer, f"{phase_prefix}_write_route_flags"):
        if route_flags:
            write_flags(knowledge, "repair.route_evidence", route_flags, source_layer="repair", source_module="job_context")
            fmt = str(route_payload.get("format") or "").lower()
            format_namespace = "format.7z" if fmt in {"7z", "seven_zip"} else "format.zip"
            write_payload(knowledge, format_namespace, {"route_evidence_flags": route_flags}, source_layer="repair", source_module="job_context")
        if damage_flags:
            write_flags(knowledge, "repair.damage", damage_flags, source_layer="repair", source_module="job_context")
    with _phase(phase_timer, f"{phase_prefix}_write_source_derivation"):
        source_derivation = route_payload.get("source_derivation") if isinstance(route_payload.get("source_derivation"), dict) else {}
        if source_derivation:
            write_payload(knowledge, "source.derivation", source_derivation, source_layer="repair", source_module="job_context")
    with _phase(phase_timer, f"{phase_prefix}_write_zip_structure"):
        structure = route_payload.get("zip_structure_features")
        if isinstance(structure, dict):
            write_payload(knowledge, "format.zip", {"structure": structure}, source_layer="repair", source_module="job_context")
        tags = route_payload.get("zip_container_tags")
        if isinstance(tags, list):
            write_payload(knowledge, "format.zip", {"container_tags": tags}, source_layer="repair", source_module="job_context")
        seven_structure = route_payload.get("seven_zip_structure") or route_payload.get("seven_zip_structure_features")
        if isinstance(seven_structure, dict):
            write_payload(knowledge, "format.7z", {"structure": seven_structure}, source_layer="repair", source_module="job_context")
        seven_tags = route_payload.get("seven_zip_container_tags")
        if isinstance(seven_tags, list):
            write_payload(knowledge, "format.7z", {"container_tags": seven_tags}, source_layer="repair", source_module="job_context")
    with _phase(phase_timer, f"{phase_prefix}_write_damage_profile"):
        if route_payload.get("damage_profile"):
            write_payload(knowledge, "source", {"profile": str(route_payload.get("damage_profile") or "")}, source_layer="repair", source_module="job_context")
    with _phase(phase_timer, f"{phase_prefix}_commit"):
        commit_task_knowledge(task, knowledge, phase_timer=phase_timer, phase_prefix=f"{phase_prefix}_commit")
    with _phase(phase_timer, f"{phase_prefix}_return_to_dict"):
        return knowledge.to_dict()


def write_repair_result(
    task: ArchiveTask,
    result: RepairResult,
    *,
    phase: str = "repair",
    archive_repaired: bool | None = None,
    phase_timer: Callable[..., Any] | None = None,
    phase_prefix: str = "write_repair_result",
) -> None:
    with _phase(phase_timer, f"{phase_prefix}_ensure_knowledge"):
        knowledge = ensure_knowledge(task)
    with _phase(phase_timer, f"{phase_prefix}_compact_payload"):
        payload = _compact_repair_result_payload(result)
    with _phase(phase_timer, f"{phase_prefix}_append_history"):
        append_history(knowledge, "repair.history.items", payload, source_layer="repair", source_module=result.module_name)
    with _phase(phase_timer, f"{phase_prefix}_write_last_result"):
        write_payload(knowledge, "repair.last_result", payload, source_layer="repair", source_module=result.module_name)
    with _phase(phase_timer, f"{phase_prefix}_write_flags"):
        if result.module_name:
            write_flags(knowledge, "repair.history", [f"already_tried:{result.module_name}"], source_layer="repair", source_module=result.module_name)
        diagnosis = result.diagnosis if isinstance(result.diagnosis, dict) else {}
        for key, namespace in (("patch_facts", "repair.patch_facts"), ("residual_facts", "repair.residual")):
            values = diagnosis.get(key)
            if isinstance(values, list):
                write_flags(knowledge, namespace, [str(item) for item in values], source_layer="repair", source_module=result.module_name)
    with _phase(phase_timer, f"{phase_prefix}_write_status"):
        write_payload(knowledge, "repair", {"status": result.status, "phase": phase}, source_layer="repair", source_module=result.module_name)
    with _phase(phase_timer, f"{phase_prefix}_write_archive_status"):
        if archive_repaired is not None:
            write_payload(knowledge, "archive", {"repaired": bool(archive_repaired)}, source_layer="repair", source_module=result.module_name)
    with _phase(phase_timer, f"{phase_prefix}_commit"):
        commit_task_knowledge(task, knowledge, phase_timer=phase_timer, phase_prefix=f"{phase_prefix}_commit")


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


def write_repair_loop_update(
    task: ArchiveTask,
    loop_payload: dict[str, Any],
    *,
    stop_reason: str = "",
    stop_payload: dict[str, Any] | None = None,
) -> None:
    knowledge = ensure_knowledge(task)
    payload = dict(loop_payload or {})
    write_payload(
        knowledge,
        "repair.loop",
        payload,
        source_layer="repair",
        source_module="loop",
    )
    if stop_reason:
        details = dict(stop_payload or {})
        write_payload(
            knowledge,
            "repair.stop",
            {"reason": str(stop_reason or ""), "details": details},
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
    loop_payload = dict(payload or {})
    write_payload(
        knowledge,
        "repair.loop",
        loop_payload,
        source_layer="repair",
        source_module="loop",
    )
    commit_task_knowledge(task, knowledge)


def write_repair_candidate_log(task: ArchiveTask, entries: list[dict[str, Any]], *, path: str = "") -> None:
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "repair",
        {
            "candidate_log": [dict(item) for item in entries[-200:] if isinstance(item, dict)],
            **({"candidate_log_path": str(path)} if path else {}),
        },
        source_layer="repair",
        source_module="candidate_log",
    )
    commit_task_knowledge(task, knowledge)


def write_repair_archive_status(task: ArchiveTask, *, password: str | None = None, repaired: bool | None = None) -> None:
    knowledge = ensure_knowledge(task)
    payload: dict[str, Any] = {}
    if password is not None:
        payload["password"] = str(password)
    if repaired is not None:
        payload["repaired"] = bool(repaired)
    if payload:
        write_payload(knowledge, "archive", payload, source_layer="repair", source_module="stage")
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
    output_quality = {
        "score": float(getattr(verification, "output_quality_score", 0.0) or 0.0),
        "file_count": int(getattr(verification, "output_file_count", 0) or 0),
        "total_bytes": int(getattr(verification, "output_total_bytes", 0) or 0),
        "complete_ratio": float(getattr(verification, "output_complete_ratio", 0.0) or 0.0),
        "failed_ratio": float(getattr(verification, "output_failed_ratio", 0.0) or 0.0),
        "empty": bool(getattr(verification, "output_empty", True)),
        "confidence": float(getattr(verification, "output_confidence", 0.0) or 0.0),
    }
    return {
        "completeness": verification.completeness,
        "recoverable_upper_bound": verification.recoverable_upper_bound,
        "assessment_status": verification.assessment_status,
        "content_integrity": verification.content_integrity,
        "container_integrity": verification.container_integrity,
        "verification_strength": verification.verification_strength,
        "total_item_count": verification.total_item_count,
        "verified_item_count": verification.verified_item_count,
        "archive_walk_complete": verification.archive_walk_complete,
        "decision_hint": verification.decision_hint,
        "complete_files": verification.complete_files,
        "partial_files": verification.partial_files,
        "failed_files": verification.failed_files,
        "missing_files": verification.missing_files,
        "unverified_files": verification.unverified_files,
        "output_quality_score": output_quality["score"],
        "output_file_count": output_quality["file_count"],
        "output_total_bytes": output_quality["total_bytes"],
        "output_complete_ratio": output_quality["complete_ratio"],
        "output_failed_ratio": output_quality["failed_ratio"],
        "output_empty": output_quality["empty"],
        "output_confidence": output_quality["confidence"],
        "output_quality": output_quality,
        "archive_coverage": asdict(verification.archive_coverage),
        "repair_hints": dict(verification.repair_hints or {}),
    }


def _compact_repair_result_payload(result: RepairResult) -> dict[str, Any]:
    diagnosis = result.diagnosis if isinstance(result.diagnosis, dict) else {}
    candidate_selection = diagnosis.get("candidate_selection") if isinstance(diagnosis.get("candidate_selection"), dict) else {}
    candidate_features = diagnosis.get("candidate_features") if isinstance(diagnosis.get("candidate_features"), dict) else {}
    repaired_input = result.repaired_input if isinstance(result.repaired_input, dict) else {}
    return {
        "ok": bool(result.ok),
        "status": result.status,
        "module_name": result.module_name,
        "repair_name": str(candidate_features.get("repair_name") or diagnosis.get("repair_name") or ""),
        "native_target": str(candidate_features.get("native_target") or diagnosis.get("native_target") or ""),
        "candidate_id": str(candidate_selection.get("selected_candidate_id") or candidate_features.get("candidate_id") or ""),
        "source_digest": str(candidate_selection.get("source_digest") or diagnosis.get("source_digest") or ""),
        "actions": list(result.actions or []),
        "diagnosis": {
            "patch_facts": [str(item) for item in diagnosis.get("patch_facts") or [] if str(item)],
            "residual_facts": [str(item) for item in diagnosis.get("residual_facts") or [] if str(item)],
            "candidate_selection": dict(candidate_selection),
            **_compact_policy_loop(diagnosis),
            **{
                key: diagnosis.get(key)
                for key in ("failure_kind", "failure_stage", "native_status", "message")
                if diagnosis.get(key) not in (None, "", [], {})
            },
        },
        "repaired_input": _compact_repaired_input(repaired_input),
    }


def _compact_policy_loop(diagnosis: dict[str, Any]) -> dict[str, Any]:
    loop = diagnosis.get("policy_loop") if isinstance(diagnosis.get("policy_loop"), dict) else {}
    if not loop:
        return {}
    payload: dict[str, Any] = {
        "policy_loop": {
            key: loop.get(key)
            for key in (
                "policy_step",
                "terminal_action",
                "stop_reason",
                "patch_depth",
                "patch_digest",
                "graph_summary",
                "current_node_id",
                "best_node_id",
                "final_state_selection",
                "policy_stop_requested",
                "graph_operation",
            )
            if loop.get(key) not in (None, "", [], {})
        }
    }
    graph = loop.get("graph") if isinstance(loop.get("graph"), dict) else {}
    if graph:
        payload["policy_loop"]["graph"] = graph
    rounds = loop.get("rounds") if isinstance(loop.get("rounds"), list) else []
    if rounds:
        payload["policy_loop"]["rounds"] = [
            {
                key: item.get(key)
                for key in (
                    "round",
                    "node_id",
                    "patch_digest",
                    "patch_depth",
                    "current_recovery",
                    "best_seen_recovery",
                    "graph_action",
                    "graph_summary",
                    "stop_readiness",
                )
                if isinstance(item, dict) and item.get(key) not in (None, "", [], {})
            }
            for item in rounds[-8:]
            if isinstance(item, dict)
        ]
    return payload


def _compact_repaired_input(repaired_input: dict[str, Any]) -> dict[str, Any]:
    if not repaired_input:
        return {}
    output: dict[str, Any] = {}
    for key in ("kind", "format_hint", "format", "path", "patch_digest"):
        if repaired_input.get(key) not in (None, "", [], {}):
            output[key] = repaired_input.get(key)
    if repaired_input.get("ranges"):
        output["range_count"] = len(repaired_input.get("ranges") or [])
    if repaired_input.get("parts"):
        output["part_count"] = len(repaired_input.get("parts") or [])
    return output


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
