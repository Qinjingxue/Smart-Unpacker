from __future__ import annotations

from typing import Any

from sunpack.repair.candidate import RepairCandidate, candidate_feature_payload
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.repair.job import RepairJob
from sunpack.support import archive_knowledge_projection as knowledge_view


FEATURE_CONTRACT_VERSION = 3

_ROUTE_VISIBLE_DAMAGE_FLAGS = {
    "carrier_archive",
    "carrier_prefix",
    "central_directory_bad",
    "central_directory_count_bad",
    "central_directory_offset_bad",
    "checksum_error",
    "crc_error",
    "data_descriptor",
    "duplicate_entries",
    "exact_match_failed",
    "extra_field_bad",
    "extra_field_length_bad",
    "filename_encoding_bad",
    "input_truncated",
    "local_header_bad",
    "local_header_conflict",
    "local_header_recovery",
    "missing_volume",
    "missing_volume_unavailable",
    "partial_entries_remaining",
    "payload_hash_mismatch",
    "raw_filename_bytes",
    "sfx",
    "split_archive",
    "split_sidecars_available",
    "tail_volume_truncated",
    "zip64",
    "zip64_eocd_bad",
    "zip64_extra_bad",
    "zip64_extra_present",
    "zip64_extra_size_bad",
    "zip64_locator_bad",
}


def policy_candidate_payload(job: RepairJob, candidate: RepairCandidate, *, index: int = 0) -> dict[str, Any]:
    payload = candidate_feature_payload(candidate)
    runtime_context = runtime_context_from_job(job, candidate=candidate)
    candidate_proposal = candidate_proposal_from_payload(payload, job=job)
    return {
        **_public_candidate_payload(payload),
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "round": _int(getattr(job, "attempts", 0)),
        "material_format": str(candidate.format or (runtime_context.get("analysis_summary") or {}).get("format") or ""),
        "current_rank": int(index),
        "branchable": _candidate_branchable(payload),
        "runtime_context": runtime_context,
        "candidate_proposal": candidate_proposal,
    }


def runtime_context_from_job(job: RepairJob, *, candidate: RepairCandidate | None = None) -> dict[str, Any]:
    knowledge = _effective_job_knowledge(job)
    source = _dict_at(knowledge, "source.input")
    failure = _dict_at(knowledge, "extraction.failure")
    diagnostics = _dict_at(knowledge, "extraction.diagnostics")
    history = knowledge_view.repair_history_summary(knowledge)
    route_context = knowledge_view.repair_route_context(knowledge)
    worker = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    verification_payload = _dict_at(knowledge, "verification.summary")
    coverage = failure.get("archive_coverage") if isinstance(failure.get("archive_coverage"), dict) else _dict_at(knowledge, "verification.summary.archive_coverage")
    repair_hints = failure.get("repair_hints") if isinstance(failure.get("repair_hints"), dict) else {}
    previous_actions = _list_values(history, "previous_actions") or _list_values(history, "path_actions")
    previous_modules = _list_values(history, "previous_modules") or _list_values(history, "path_modules")
    damage_flags = list(route_context.get("damage_flags") or [])
    prepass = _dict_at(knowledge, "analysis.prepass")
    fuzzy = _dict_at(knowledge, "analysis.fuzzy")
    evidence_payload = _dict_at(knowledge, "analysis.evidence")
    analysis_summary = _dict_at(knowledge, "analysis.summary")
    route_evidence_flags = list(route_context.get("route_evidence_flags") or [])
    knowledge_payload = knowledge.to_dict()
    feature_contract_miss = _feature_contract_miss(knowledge)
    return {
        "knowledge_projection": {
            "version": FEATURE_CONTRACT_VERSION,
            "source_count": 1 if knowledge_payload else 0,
            "has_archive_knowledge": bool(knowledge_payload),
            "feature_contract_miss": feature_contract_miss,
            "source_fingerprint": knowledge_view.source_fingerprint(knowledge),
        },
        "analysis_summary": {
            "format": str(analysis_summary.get("format") or ""),
            "confidence": _float(analysis_summary.get("confidence")),
            "evidence_format": str(evidence_payload.get("format") or evidence_payload.get("archive_type") or ""),
            "evidence_confidence": _float(evidence_payload.get("confidence")),
            "prepass_status": str(prepass.get("status") or ""),
            "prepass_format": str(prepass.get("format") or prepass.get("selected_format") or ""),
            "prepass_confidence": _float(prepass.get("confidence")),
            "fuzzy_status": str(fuzzy.get("status") or ""),
            "fuzzy_archive_type": str(fuzzy.get("archive_type") or fuzzy.get("format") or ""),
            "fuzzy_confidence": _float(fuzzy.get("confidence")),
        },
        "analysis_native_probe": _analysis_native_probe(job, source=source, prepass=prepass, history=history, route_evidence_flags=route_evidence_flags),
        "fuzzy_profile": _fuzzy_profile(job),
        "extraction_summary": {
            "has_failure": bool(failure),
            "failure_stage": str(failure.get("failure_stage") or diagnostics.get("failure_stage") or worker.get("failure_stage") or ""),
            "failure_kind": str(failure.get("failure_kind") or diagnostics.get("failure_kind") or worker.get("failure_kind") or ""),
            "status": str(failure.get("status") or worker.get("status") or ""),
            "native_status": str(worker.get("native_status") or diagnostics.get("native_status") or ""),
            "files_written": _int(worker.get("files_written") if worker else diagnostics.get("files_written")),
            "bytes_written": _int(worker.get("bytes_written") if worker else diagnostics.get("bytes_written")),
            "error_kind_present": bool(failure.get("error") or diagnostics.get("error") or worker.get("message")),
            "worker_returncode": _optional_int(diagnostics.get("returncode")),
        },
        "verification_summary": {
            "decision_hint": str(failure.get("decision_hint") or verification_payload.get("decision_hint") or ""),
            "assessment_status": str(failure.get("assessment_status") or verification_payload.get("assessment_status") or ""),
            "source_integrity": str(failure.get("source_integrity") or verification_payload.get("source_integrity") or ""),
            "completeness": _float(failure.get("completeness", verification_payload.get("completeness"))),
            "recoverable_upper_bound": _float(failure.get("recoverable_upper_bound", verification_payload.get("recoverable_upper_bound")), default=1.0),
            "complete_files": _int(failure.get("complete_files", verification_payload.get("complete_files"))),
            "partial_files": _int(failure.get("partial_files", verification_payload.get("partial_files"))),
            "failed_files": _int(failure.get("failed_files", verification_payload.get("failed_files"))),
            "missing_files": _int(failure.get("missing_files", verification_payload.get("missing_files"))),
            "unverified_files": _int(failure.get("unverified_files", verification_payload.get("unverified_files"))),
            "archive_coverage": {
                "completeness": _float(coverage.get("completeness")),
                "file_coverage": _float(coverage.get("file_coverage")),
                "byte_coverage": _float(coverage.get("byte_coverage")),
                "expected_files": _int(coverage.get("expected_files")),
                "matched_files": _int(coverage.get("matched_files")),
                "complete_files": _int(coverage.get("complete_files")),
                "partial_files": _int(coverage.get("partial_files")),
                "failed_files": _int(coverage.get("failed_files")),
                "missing_files": _int(coverage.get("missing_files")),
            },
        },
        "verification_per_file": _verification_per_file(failure),
        "repair_hints": {
            "selected_format": str(repair_hints.get("selected_format") or ""),
            "analysis_status": str(repair_hints.get("analysis_status") or ""),
            "source_integrity": str(repair_hints.get("source_integrity") or ""),
            "likely_truncated": bool(repair_hints.get("likely_truncated", False)),
            "likely_payload_damage": bool(repair_hints.get("likely_payload_damage", False)),
            "boundary_untrusted": bool(repair_hints.get("boundary_untrusted", False)),
            "damage_flags": list(repair_hints.get("damage_flags") or route_evidence_flags or []),
            "damage_flag_count": len(repair_hints.get("damage_flags") or route_evidence_flags or []),
            "failure_stage": str(repair_hints.get("failure_stage") or worker.get("failure_stage") or ""),
            "failure_kind": str(repair_hints.get("failure_kind") or worker.get("failure_kind") or ""),
            "native_status": str(repair_hints.get("native_status") or worker.get("native_status") or ""),
            "worker_message_length": len(str(worker.get("message") or "")),
        },
        "previous_actions": list(previous_actions),
        "previous_action_count": len(previous_actions),
        "previous_modules": list(previous_modules),
        "previous_module_count": len(previous_modules),
        "runtime_state_summary": _runtime_state_summary(history.get("runtime_state_summary") if isinstance(history.get("runtime_state_summary"), dict) else {}),
        "job_summary": {
            "format": str(analysis_summary.get("format") or ""),
            "confidence": _float(analysis_summary.get("confidence")),
            "damage_flags": damage_flags,
            "damage_flag_count": len(damage_flags),
            "route_evidence_flags": route_evidence_flags,
            "route_evidence_flag_count": len(route_evidence_flags),
            "repair_history_flags": list(history.get("repair_history_flags") or []),
            "repair_history_flag_count": len(history.get("repair_history_flags") or []),
            "residual_damage_flags": list(route_context.get("residual_damage_flags") or history.get("residual_damage_flags") or []),
            "residual_damage_flag_count": len(route_context.get("residual_damage_flags") or history.get("residual_damage_flags") or []),
            "attempts": _int(job.attempts),
            "has_password": job.password is not None,
            "source_kind": str(source.get("kind") or source.get("open_mode") or ""),
            "source_format_hint": str(source.get("format_hint") or source.get("format") or ""),
            "has_archive_state": _dict_at(knowledge, "archive.state") != {},
            "archive_state_patch_count": len(_dict_at(knowledge, "archive.state").get("patches") or _dict_at(knowledge, "archive.state").get("patch_stack") or []),
        },
        "native_feedback": _native_feedback(candidate),
    }


def candidate_proposal_from_payload(payload: dict[str, Any], *, job: RepairJob | None = None) -> dict[str, Any]:
    output = {
        key: payload.get(key)
        for key in (
            "module",
            "repair_name",
            "atomic_action_group",
            "native_key",
            "native_target",
            "candidate_status",
            "route_family",
            "route_required_flags_matched",
            "route_reject_reason",
            "native_target_mismatch",
            "format",
            "confidence",
            "score_hint",
            "actions",
            "damage_flags",
            "patch_cost",
            "requires_native_validation",
            "has_archive_state_plan",
            "requires_materialization",
            "plan_kind",
            "estimated_cost",
            "input_kind",
            "partial",
            "lazy",
            "patch_span_count",
            "patch_operation_count",
            "affected_entry_count",
            "patch_facts",
            "residual_facts",
            "raw_name_bytes_preserved",
            "raw_name_source",
            "split_sidecars_available",
            "logical_stream_built",
            "after_archive_carrier_crop",
        )
        if key in payload
    }
    validation = payload.get("validation_details")
    if isinstance(validation, dict):
        output["validation_details"] = {
            key: validation.get(key)
            for key in (
                "policy",
                "crc_match_count",
                "kept_entries",
                "dropped_entries",
                "duplicate_group_count",
                "kept_entry_crc_match_count",
                "kept_payload_verified_count",
                "dropped_entry_count",
                "ambiguous_duplicate_group_count",
                "native_target",
                "accepted",
                "raw_filename_bytes_preserved",
            )
            if key in validation
        }
    return output


def _public_candidate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    validation = payload.get("validation_details") if isinstance(payload.get("validation_details"), dict) else {}
    safe_validation = {
        key: validation.get(key)
        for key in (
            "policy",
            "crc_match_count",
            "kept_entries",
            "dropped_entries",
            "duplicate_group_count",
            "kept_entry_crc_match_count",
            "kept_payload_verified_count",
            "dropped_entry_count",
            "ambiguous_duplicate_group_count",
            "native_target",
            "accepted",
            "raw_filename_bytes_preserved",
        )
        if key in validation
    }
    return {
        "candidate_id": payload.get("candidate_id"),
        "module": payload.get("module"),
        "module_name": payload.get("module_name") or payload.get("module"),
        "repair_name": payload.get("repair_name"),
        "native_key": payload.get("native_key"),
        "native_target": payload.get("native_target"),
        "candidate_status": payload.get("candidate_status"),
        "atomic_action_group": payload.get("atomic_action_group"),
        "route_family": payload.get("route_family"),
        "native_target_mismatch": payload.get("native_target_mismatch"),
        "format": payload.get("format"),
        "status": payload.get("status"),
        "partial": payload.get("partial"),
        "lazy": payload.get("lazy"),
        "materialized": payload.get("materialized"),
        "requires_native_validation": payload.get("requires_native_validation"),
        "plan_kind": payload.get("plan_kind"),
        "patch_cost": payload.get("patch_cost"),
        "patch_span_count": payload.get("patch_span_count"),
        "patch_operation_count": payload.get("patch_operation_count"),
        "affected_entry_count": payload.get("affected_entry_count"),
        "patch_facts": payload.get("patch_facts"),
        "residual_facts": payload.get("residual_facts"),
        "raw_name_bytes_preserved": payload.get("raw_name_bytes_preserved"),
        "raw_name_source": payload.get("raw_name_source"),
        "split_sidecars_available": payload.get("split_sidecars_available"),
        "logical_stream_built": payload.get("logical_stream_built"),
        "after_archive_carrier_crop": payload.get("after_archive_carrier_crop"),
        "validation_details": safe_validation,
        "validation_count": payload.get("validation_count"),
        "native_validation_score": payload.get("native_validation_score"),
    }


def _analysis_native_probe(
    job: RepairJob,
    *,
    source: dict[str, Any],
    prepass: dict[str, Any],
    history: dict[str, Any],
    route_evidence_flags: list[str],
) -> dict[str, Any]:
    knowledge = _effective_job_knowledge(job)
    route_context = knowledge_view.repair_route_context(knowledge)
    zip_facts = knowledge_view.zip_runtime_facts(knowledge)
    damage_flags = list(route_context.get("damage_flags") or [])
    analysis_summary = _dict_at(knowledge, "analysis.summary")
    probe: dict[str, Any] = {
        "format": str(analysis_summary.get("format") or ""),
        "confidence": _float(analysis_summary.get("confidence")),
        "damage_flags": list(damage_flags),
        "damage_flag_count": len(damage_flags),
        "attempts": _int(job.attempts),
        "has_password": job.password is not None,
        "source_kind": str(source.get("kind") or source.get("open_mode") or ""),
        "source_format_hint": str(source.get("format_hint") or source.get("format") or ""),
        "has_archive_state": _dict_at(knowledge, "archive.state") != {},
    }
    structure = zip_facts.get("structure") if isinstance(zip_facts.get("structure"), dict) else {}
    for key, value in structure.items():
        probe[key] = _safe_feature_value(value)
    tags = zip_facts.get("container_tags") if isinstance(zip_facts.get("container_tags"), list) else []
    probe["zip_container_tag_count"] = len(tags)
    for tag in tags:
        if str(tag):
            probe[f"zip_container_tag_{tag}"] = 1
    fuzzy = prepass.get("fuzzy") if isinstance(prepass.get("fuzzy"), dict) else {}
    profile = fuzzy.get("binary_profile") if isinstance(fuzzy.get("binary_profile"), dict) else {}
    entropy = profile.get("entropy_profile") if isinstance(profile.get("entropy_profile"), dict) else {}
    for key in ("head_entropy", "middle_entropy", "tail_entropy", "avg_entropy", "overall_class"):
        if key in entropy:
            probe[key] = _safe_feature_value(entropy[key])
    byte_class = profile.get("byte_class_profile") if isinstance(profile.get("byte_class_profile"), dict) else {}
    for section, bc in (("head", byte_class.get("head")), ("tail", byte_class.get("tail"))):
        if isinstance(bc, dict):
            for metric in ("text", "binary", "zero", "printable_ratio", "control_ratio", "high_bit_ratio"):
                if metric in bc:
                    probe[f"byte_class_{section}_{metric}"] = _float(bc.get(metric))
    ngram = profile.get("ngram_sketch") if isinstance(profile.get("ngram_sketch"), dict) else {}
    if "magic_like_density_per_mb" in ngram:
        probe["magic_like_density_per_mb"] = _float(ngram.get("magic_like_density_per_mb"))
    for flag in route_evidence_flags:
        if str(flag):
            probe[f"route_evidence_{flag}"] = 1
    for flag in history.get("repair_history_flags") or []:
        if str(flag):
            probe[f"repair_history_{flag}"] = 1
    for flag in history.get("residual_damage_flags") or []:
        if str(flag):
            probe[f"residual_damage_{flag}"] = 1
    return probe


def _route_evidence_flags(
    job: RepairJob,
    *,
    source: dict[str, Any],
    prepass: dict[str, Any],
    history: dict[str, Any],
) -> list[str]:
    knowledge = _effective_job_knowledge(job)
    route_context = knowledge_view.repair_route_context(knowledge)
    return [
        str(flag)
        for flag in route_context.get("route_evidence_flags") or []
        if str(flag) in _ROUTE_VISIBLE_DAMAGE_FLAGS or str(flag)
    ]


def _fuzzy_profile(job: RepairJob) -> dict[str, Any]:
    knowledge = _effective_job_knowledge(job)
    profile = _dict_at(knowledge, "analysis.fuzzy")
    if not profile:
        prepass = _dict_at(knowledge, "analysis.prepass")
        fuzzy = prepass.get("fuzzy") if isinstance(prepass.get("fuzzy"), dict) else {}
        if isinstance(fuzzy, dict) and isinstance(fuzzy.get("binary_profile"), dict):
            profile = fuzzy["binary_profile"]
    if not profile:
        return {}
    entropy = profile.get("entropy_profile") if isinstance(profile.get("entropy_profile"), dict) else {}
    byte_class = profile.get("byte_class_profile") if isinstance(profile.get("byte_class_profile"), dict) else {}
    head_bc = byte_class.get("head") if isinstance(byte_class.get("head"), dict) else {}
    tail_bc = byte_class.get("tail") if isinstance(byte_class.get("tail"), dict) else {}
    avg_bc = byte_class.get("average") if isinstance(byte_class.get("average"), dict) else {}
    ngram = profile.get("ngram_sketch") if isinstance(profile.get("ngram_sketch"), dict) else {}
    run_profile = profile.get("run_profile") if isinstance(profile.get("run_profile"), dict) else {}
    tail_run = run_profile.get("tail_run") if isinstance(run_profile.get("tail_run"), dict) else {}
    longest_zero = run_profile.get("longest_zero_run") if isinstance(run_profile.get("longest_zero_run"), dict) else {}
    longest_ff = run_profile.get("longest_ff_run") if isinstance(run_profile.get("longest_ff_run"), dict) else {}
    return {
        "status": str(profile.get("status") or ""),
        "archive_type": str(profile.get("archive_type") or profile.get("format") or ""),
        "confidence": _float(profile.get("confidence")),
        "window_bytes": _int(profile.get("window_bytes")),
        "sample_count": _int(profile.get("sample_count")),
        "hint_count": len(profile.get("hints") or []),
        "entropy_head": _float(entropy.get("head_entropy")),
        "entropy_middle": _float(entropy.get("middle_entropy")),
        "entropy_tail": _float(entropy.get("tail_entropy")),
        "entropy_avg": _float(entropy.get("avg_entropy")),
        "entropy_class": str(entropy.get("overall_class") or ""),
        "head_low_entropy": bool(entropy.get("head_low_entropy")),
        "tail_low_entropy": bool(entropy.get("tail_low_entropy")),
        "local_high_entropy": bool(entropy.get("local_high_entropy")),
        "bc_head_printable": _float(head_bc.get("printable_ratio")),
        "bc_head_control": _float(head_bc.get("control_ratio")),
        "bc_head_high_bit": _float(head_bc.get("high_bit_ratio")),
        "bc_head_zero": _float(head_bc.get("zero_ratio")),
        "bc_tail_printable": _float(tail_bc.get("printable_ratio")),
        "bc_tail_control": _float(tail_bc.get("control_ratio")),
        "bc_tail_high_bit": _float(tail_bc.get("high_bit_ratio")),
        "bc_tail_zero": _float(tail_bc.get("zero_ratio")),
        "bc_avg_printable": _float(avg_bc.get("printable_ratio")),
        "bc_avg_control": _float(avg_bc.get("control_ratio")),
        "bc_avg_high_bit": _float(avg_bc.get("high_bit_ratio")),
        "magic_like_density": _float(ngram.get("magic_like_density_per_mb")),
        "ngram_byte_top_count": len(ngram.get("byte_histogram_top") or []),
        "ngram_magic_hits_count": len(ngram.get("magic_like_hits") or []),
        "tail_padding_likely": bool(run_profile.get("tail_padding_likely")),
        "longest_zero_len": _int(longest_zero.get("length")),
        "longest_zero_offset": _optional_int(longest_zero.get("offset")),
        "longest_ff_len": _int(longest_ff.get("length")),
        "longest_ff_offset": _optional_int(longest_ff.get("offset")),
        "tail_run_byte": str(tail_run.get("byte") or ""),
        "tail_run_len": _int(tail_run.get("length")),
        "tail_run_offset": _optional_int(tail_run.get("offset")),
    }


def _verification_per_file(failure: dict[str, Any]) -> dict[str, Any]:
    observations = failure.get("file_observations")
    if not isinstance(observations, list):
        return {}
    counts: dict[str, int] = {}
    for item in observations:
        if not isinstance(item, dict):
            continue
        state = str(item.get("state") or "")
        if state:
            counts[state] = counts.get(state, 0) + 1
    return {"state_counts": counts, "observation_count": len(observations)}


def _runtime_state_summary(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "format_detected": bool(summary.get("format_detected")),
        "boundary_trusted": bool(summary.get("boundary_trusted")),
        "directory_detected": bool(summary.get("directory_detected")),
        "entry_count": _int(summary.get("entry_count")),
        "readable_entry_count": _int(summary.get("readable_entry_count")),
        "damage_flags": list(summary.get("damage_flags") or []),
        "runtime_status": str(summary.get("runtime_status") or ""),
        "runtime_score": _float(summary.get("runtime_score")),
    }


def _effective_job_knowledge(job: RepairJob) -> ArchiveKnowledge:
    return ArchiveKnowledge.from_any(getattr(job, "knowledge", {}))


def _feature_contract_miss(knowledge: ArchiveKnowledge) -> list[str]:
    required = (
        "source.input",
        "analysis.summary",
        "extraction.failure",
        "verification.summary",
        "repair.history",
    )
    return [path for path in required if knowledge.get(path) in (None, "", [], {})]


def _dict_at(knowledge: ArchiveKnowledge, path: str) -> dict[str, Any]:
    value = knowledge.get(path)
    return dict(value) if isinstance(value, dict) else {}


def _list_at(knowledge: ArchiveKnowledge, path: str) -> list[Any]:
    value = knowledge.get(path)
    return list(value) if isinstance(value, list) else []


def _native_feedback(candidate: RepairCandidate | None) -> dict[str, Any]:
    if candidate is None:
        return {}
    payload = candidate_feature_payload(candidate)
    return {
        "native_target": payload.get("native_target"),
        "candidate_status": payload.get("candidate_status"),
        "native_target_mismatch": bool(payload.get("native_target_mismatch")),
        "validation_details": payload.get("validation_details") if isinstance(payload.get("validation_details"), dict) else {},
    }


def _list_values(payload: dict[str, Any], key: str) -> list[str]:
    raw = payload.get(key)
    if isinstance(raw, (list, tuple, set)):
        return [str(item) for item in raw if str(item)]
    if isinstance(raw, str) and raw:
        return [raw]
    return []


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _safe_feature_value(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float | str):
        return value
    if value is None:
        return None
    return str(value)


def _candidate_branchable(payload: dict[str, Any]) -> bool:
    if payload.get("has_archive_state_plan"):
        return True
    if payload.get("materialized") is False and payload.get("lazy"):
        return False
    return True


def _int(value: Any) -> int:
    try:
        if value is None:
            return 0
        return int(value)
    except Exception:
        return 0


def _optional_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except Exception:
        return None


def _float(value: Any, *, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default
