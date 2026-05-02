from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sunpack.repair import RepairJob
from sunpack.repair.candidate import candidate_feature_payload


FEATURE_CONTRACT_VERSION = 2


@dataclass(frozen=True)
class RepairPrior:
    route_score: float | None = None
    fine_score: float | None = None
    generation_priority: float | None = None
    current_selector_rank: int | None = None
    module_selected_by_router: bool | None = None
    proposal_breakdowns: dict[str, Any] = field(default_factory=dict)


def build_runtime_feature_record(
    *,
    job: RepairJob,
    candidate: Any,
    previous_actions: list[str] | None = None,
    previous_modules: list[str] | None = None,
    runtime_state_summary: dict[str, Any] | None = None,
    repair_prior: RepairPrior | dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = candidate_feature_payload(candidate) if candidate is not None else {}
    prior_payload = _repair_prior_payload(repair_prior, payload)
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    path_actions = previous_actions if previous_actions is not None else failure.get("previous_actions")
    path_modules = previous_modules if previous_modules is not None else failure.get("previous_modules")
    runtime_state = _runtime_state_summary(runtime_state_summary or {})
    fuzzy = _fuzzy_profile(job)
    native_probe = _analysis_native_probe(job)
    return {
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "runtime_context": {
            "analysis_summary": _analysis_summary(job),
            "analysis_native_probe": native_probe,
            "fuzzy_profile": fuzzy,
            "extraction_summary": _extraction_summary(job),
            "verification_summary": _verification_summary(job),
            "verification_per_file": _verification_per_file(job),
            "repair_hints": _repair_hints(job),
            "previous_actions": list(path_actions or []),
            "previous_action_count": len(path_actions or []),
            "previous_modules": list(path_modules or []),
            "previous_module_count": len(path_modules or []),
            "runtime_state_summary": runtime_state,
            "job_summary": _job_summary(job),
            "native_feedback": _native_feedback(candidate),
        },
        "candidate_proposal": _candidate_proposal(payload, job=job, runtime_state_summary=runtime_state),
        "repair_prior_features": prior_payload,
    }


# ── Analysis layer ──────────────────────────────────────────────────

def _analysis_summary(job: RepairJob) -> dict[str, Any]:
    evidence = getattr(job, "analysis_evidence", None)
    prepass = job.analysis_prepass if isinstance(job.analysis_prepass, dict) else {}
    fuzzy = job.fuzzy_profile if isinstance(job.fuzzy_profile, dict) else {}
    return {
        "format": str(job.format or ""),
        "confidence": _float(job.confidence),
        "evidence_format": str(getattr(evidence, "format", "") or getattr(evidence, "archive_type", "") or ""),
        "evidence_confidence": _float(getattr(evidence, "confidence", None)),
        "prepass_status": str(prepass.get("status") or ""),
        "prepass_format": str(prepass.get("format") or prepass.get("selected_format") or ""),
        "prepass_confidence": _float(prepass.get("confidence")),
        "fuzzy_status": str(fuzzy.get("status") or ""),
        "fuzzy_archive_type": str(fuzzy.get("archive_type") or fuzzy.get("format") or ""),
        "fuzzy_confidence": _float(fuzzy.get("confidence")),
    }


def _analysis_native_probe(job: RepairJob) -> dict[str, Any]:
    """Capture the full native analysis data.

    Data sources on RepairJob (in order of richness):
    1. job.analysis_prepass — the signature prepass + fuzzy profile
    2. job.zip_structure_features — ZIP variant/container tags
    3. job.source_derivation — how the source was derived
    """
    probe = {}

    # Source 1: zip_structure_features (row-level, but accessible)
    zsf = getattr(job, "zip_structure_features", None) or {}
    if isinstance(zsf, dict):
        for key in zsf:
            probe[key] = _safe_feature_value(zsf[key])

    # Source 2: analysis_prepass carries hits and selected format
    prepass = job.analysis_prepass if isinstance(job.analysis_prepass, dict) else {}
    for key in ("status", "format", "selected_format", "confidence"):
        if key in prepass:
            probe["prepass_" + key] = prepass[key]
    hits = prepass.get("hits") if isinstance(prepass.get("hits"), list) else []
    hit_names = [str(h.get("name") or "") for h in hits if isinstance(h, dict)]
    probe["prepass_hit_count"] = len(hit_names)
    # Count by type
    for name in hit_names:
        probe[f"prepass_hit_{name}"] = 1

    # Source 3: binary_profile from prepass.fuzzy
    fuzzy = prepass.get("fuzzy") if isinstance(prepass.get("fuzzy"), dict) else {}
    profile = fuzzy.get("binary_profile") if isinstance(fuzzy.get("binary_profile"), dict) else {}
    # Extract key structural fields from the binary profile
    entropy = profile.get("entropy_profile") if isinstance(profile.get("entropy_profile"), dict) else {}
    for key in ("head_entropy", "middle_entropy", "tail_entropy", "avg_entropy", "overall_class"):
        if key in entropy:
            probe[key] = _safe_feature_value(entropy[key])
    byte_class = profile.get("byte_class_profile") if isinstance(profile.get("byte_class_profile"), dict) else {}
    for section, bc in [("head", byte_class.get("head")), ("tail", byte_class.get("tail"))]:
        if isinstance(bc, dict):
            for mk in ("text", "binary", "zero"):
                probe[f"byte_class_{section}_{mk}"] = _float(bc.get(mk))
    ngram = profile.get("ngram_sketch") if isinstance(profile.get("ngram_sketch"), dict) else {}
    probe["magic_like_density_per_mb"] = _float(ngram.get("magic_like_density_per_mb"))

    # Source 4: source_derivation (row level)
    sd = getattr(job, "source_derivation", None) or {}
    if isinstance(sd, dict):
        for key in ("format", "size", "method", "level", "zip_variant", "tool", "sample_id"):
            if key in sd:
                probe[f"source_{key}"] = _safe_feature_value(sd[key])
        tags = sd.get("zip_container_tags") or []
        if isinstance(tags, list):
            probe["source_zip_tag_count"] = len(tags)

    return probe


def _fuzzy_profile(job: RepairJob) -> dict[str, Any]:
    """Capture the fuzzy binary profile from RepairJob.fuzzy_profile.

    repair_stage._analysis_fuzzy_profile() already extracts report.fuzzy["binary_profile"]
    and stores it directly as RepairJob.fuzzy_profile. So we get the {entropy_profile, byte_class_profile, ...} dict.
    """
    profile = job.fuzzy_profile if isinstance(job.fuzzy_profile, dict) else {}

    if not profile:
        return {}

    # Entropy
    entropy = profile.get("entropy_profile") if isinstance(profile.get("entropy_profile"), dict) else {}
    # Byte class
    byte_class = profile.get("byte_class_profile") if isinstance(profile.get("byte_class_profile"), dict) else {}
    head_bc = byte_class.get("head") if isinstance(byte_class.get("head"), dict) else {}
    tail_bc = byte_class.get("tail") if isinstance(byte_class.get("tail"), dict) else {}
    avg_bc = byte_class.get("average") if isinstance(byte_class.get("average"), dict) else {}
    # Ngram
    ngram = profile.get("ngram_sketch") if isinstance(profile.get("ngram_sketch"), dict) else {}
    # Run-length
    run_profile = profile.get("run_profile") if isinstance(profile.get("run_profile"), dict) else {}
    tail_run = run_profile.get("tail_run") if isinstance(run_profile.get("tail_run"), dict) else {}
    longest_zero = run_profile.get("longest_zero_run") if isinstance(run_profile.get("longest_zero_run"), dict) else {}
    longest_ff = run_profile.get("longest_ff_run") if isinstance(run_profile.get("longest_ff_run"), dict) else {}

    return {
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
        "bc_head_ff": _float(head_bc.get("ff_ratio")),
        "bc_tail_printable": _float(tail_bc.get("printable_ratio")),
        "bc_tail_control": _float(tail_bc.get("control_ratio")),
        "bc_tail_high_bit": _float(tail_bc.get("high_bit_ratio")),
        "bc_tail_zero": _float(tail_bc.get("zero_ratio")),
        "bc_tail_ff": _float(tail_bc.get("ff_ratio")),
        "bc_avg_printable": _float(avg_bc.get("printable_ratio")),
        "bc_avg_control": _float(avg_bc.get("control_ratio")),
        "bc_avg_high_bit": _float(avg_bc.get("high_bit_ratio")),
        "bc_avg_zero": _float(avg_bc.get("zero_ratio")),
        "bc_avg_ff": _float(avg_bc.get("ff_ratio")),
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


# ── Extraction layer ───────────────────────────────────────────────

def _extraction_summary(job: RepairJob) -> dict[str, Any]:
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    diagnostics = job.extraction_diagnostics if isinstance(job.extraction_diagnostics, dict) else {}
    worker = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    progress_events = diagnostics.get("progress_events")
    if not isinstance(progress_events, list):
        progress_events = []

    # Extract the latest meaningful progress event
    last_progress = {}
    for ev in reversed(progress_events):
        if isinstance(ev, dict) and ev.get("path"):
            last_progress = ev
            break

    # Count progress events by type
    progress_kind_counts = {}
    for ev in progress_events:
        if isinstance(ev, dict):
            kind = str(ev.get("kind") or ev.get("status") or "unknown")
            progress_kind_counts[kind] = progress_kind_counts.get(kind, 0) + 1

    # Worker process diagnostics
    proc = diagnostics.get("process") if isinstance(diagnostics.get("process"), dict) else {}
    process_failure = diagnostics.get("process_failure") if isinstance(diagnostics.get("process_failure"), dict) else {}

    return {
        "has_failure": bool(failure),
        "failure_stage": str(failure.get("failure_stage") or diagnostics.get("failure_stage") or worker.get("failure_stage") or ""),
        "failure_kind": str(failure.get("failure_kind") or diagnostics.get("failure_kind") or worker.get("failure_kind") or ""),
        "status": str(failure.get("status") or worker.get("status") or ""),
        "native_status": str(worker.get("native_status") or diagnostics.get("native_status") or ""),
        "files_written": _int(worker.get("files_written") if worker else diagnostics.get("files_written")),
        "bytes_written": _int(worker.get("bytes_written") if worker else diagnostics.get("bytes_written")),
        "error_kind_present": bool(failure.get("error") or diagnostics.get("error") or worker.get("message")),
        "worker_returncode": _optional_int(diagnostics.get("returncode")),
        "progress_event_count": len(progress_events),
        "progress_kind_counts": progress_kind_counts,
        "last_progress_path": str(last_progress.get("path") or ""),
        "last_progress_state": str(last_progress.get("state") or last_progress.get("status") or ""),
        "last_progress_percent": _float(last_progress.get("progress") or last_progress.get("percent")),
        "last_progress_bytes": _int(last_progress.get("bytes_written")),
        "process_failure_stage": str(process_failure.get("failure_stage") or ""),
        "process_failure_kind": str(process_failure.get("failure_kind") or ""),
        "stderr_tail_lines": len(proc.get("stderr_tail") or []),
    }


# ── Verification layer ─────────────────────────────────────────────

def _verification_summary(job: RepairJob) -> dict[str, Any]:
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    coverage = failure.get("archive_coverage") if isinstance(failure.get("archive_coverage"), dict) else {}
    return {
        "decision_hint": str(failure.get("decision_hint") or ""),
        "assessment_status": str(failure.get("assessment_status") or ""),
        "source_integrity": str(failure.get("source_integrity") or ""),
        "completeness": _float(failure.get("completeness")),
        "recoverable_upper_bound": _float(failure.get("recoverable_upper_bound"), default=1.0),
        "complete_files": _int(failure.get("complete_files")),
        "partial_files": _int(failure.get("partial_files")),
        "failed_files": _int(failure.get("failed_files")),
        "missing_files": _int(failure.get("missing_files")),
        "unverified_files": _int(failure.get("unverified_files")),
        "archive_coverage": {
            "completeness": _float(coverage.get("completeness")),
            "file_coverage": _float(coverage.get("file_coverage")),
            "byte_coverage": _float(coverage.get("byte_coverage")),
            "expected_files": _int(coverage.get("expected_files")),
            "expected_bytes": _int(coverage.get("expected_bytes")),
            "matched_files": _int(coverage.get("matched_files")),
            "matched_bytes": _int(coverage.get("matched_bytes")),
            "complete_files": _int(coverage.get("complete_files")),
            "complete_bytes": _int(coverage.get("complete_bytes")),
            "partial_files": _int(coverage.get("partial_files")),
            "failed_files": _int(coverage.get("failed_files")),
            "missing_files": _int(coverage.get("missing_files")),
        },
    }


def _verification_per_file(job: RepairJob) -> dict[str, Any]:
    """Extract per-file verification observations.

    The VerificationResult.file_observations list contains per-file state:
    complete/partial/failed/missing with bytes_written, CRC, progress.
    This flows into RepairJob.extraction_failure as 'file_observations' or
    from the archive_coverage 'observations' field.
    """
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    observations = failure.get("file_observations")
    if not isinstance(observations, list):
        coverage = failure.get("archive_coverage") if isinstance(failure.get("archive_coverage"), dict) else {}
        observations = coverage.get("observations") or []

    if not observations:
        return {}

    # Aggregate per-file state counts
    state_counts = {}
    total_obs = 0
    failed_names = []
    partial_names = []
    missing_names = []
    total_bytes_written = 0
    total_expected_bytes = 0
    crc_mismatch_count = 0
    crc_match_count = 0
    truncation_count = 0

    for obs in observations:
        if not isinstance(obs, dict):
            continue
        total_obs += 1
        state = str(obs.get("state") or "")
        state_counts[state] = state_counts.get(state, 0) + 1

        name = str(obs.get("path") or obs.get("archive_path") or "")
        if state == "failed":
            failed_names.append(name)
        elif state == "partial":
            partial_names.append(name)
        elif state == "missing":
            missing_names.append(name)

        bw = _int(obs.get("bytes_written"))
        es = _int(obs.get("expected_size"))
        total_bytes_written += bw
        total_expected_bytes += es

        if es > 0:
            progress = bw / es if es > 0 else 0.0
            if progress > 0 and progress < 0.999 and state != "complete":
                truncation_count += 1

        details = obs.get("details") if isinstance(obs.get("details"), dict) else {}
        crc_expected = _optional_int(obs.get("crc_expected"))
        crc_actual = _optional_int(obs.get("crc_actual"))
        if crc_expected is not None and crc_actual is not None:
            if crc_expected == crc_actual:
                crc_match_count += 1
            else:
                crc_mismatch_count += 1

    return {
        "observation_count": total_obs,
        "state_complete": state_counts.get("complete", 0),
        "state_partial": state_counts.get("partial", 0),
        "state_failed": state_counts.get("failed", 0),
        "state_missing": state_counts.get("missing", 0),
        "failed_names": failed_names[:10],
        "partial_names": partial_names[:10],
        "missing_names": missing_names[:10],
        "failed_name_count": len(failed_names),
        "partial_name_count": len(partial_names),
        "missing_name_count": len(missing_names),
        "total_bytes_written": total_bytes_written,
        "total_expected_bytes": total_expected_bytes,
        "byte_recovery_ratio": _float(total_bytes_written / max(1, total_expected_bytes)),
        "crc_match_count": crc_match_count,
        "crc_mismatch_count": crc_mismatch_count,
        "truncation_count": truncation_count,
    }


def _repair_hints(job: RepairJob) -> dict[str, Any]:
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    hints = failure.get("repair_hints") if isinstance(failure.get("repair_hints"), dict) else {}
    diagnostics = job.extraction_diagnostics if isinstance(job.extraction_diagnostics, dict) else {}
    worker = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    return {
        "selected_format": str(hints.get("selected_format") or ""),
        "analysis_status": str(hints.get("analysis_status") or ""),
        "analysis_confidence": _float(hints.get("analysis_confidence")),
        "source_integrity": str(hints.get("source_integrity") or ""),
        "likely_truncated": bool(hints.get("likely_truncated", False)),
        "likely_payload_damage": bool(hints.get("likely_payload_damage", False)),
        "boundary_untrusted": bool(hints.get("boundary_untrusted", False)),
        # Structural details that were previously only in booleans
        "segment_start": _optional_int(hints.get("segment_start")),
        "segment_end": _optional_int(hints.get("segment_end")),
        "damage_flags": list(hints.get("damage_flags") or []),
        "damage_flag_count": len(hints.get("damage_flags") or []),
        # Worker/7z diagnostics
        "failure_stage": str(hints.get("failure_stage") or worker.get("failure_stage") or ""),
        "failure_kind": str(hints.get("failure_kind") or worker.get("failure_kind") or ""),
        "native_status": str(hints.get("native_status") or worker.get("native_status") or ""),
        # Worker message (often contains per-file error details)
        "worker_message": str(worker.get("message") or ""),
        "worker_message_length": len(str(worker.get("message") or "")),
    }


# ── Runtime state ──────────────────────────────────────────────────

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


def _job_summary(job: RepairJob) -> dict[str, Any]:
    archive_state = job.archive_state
    source = job.source_input if isinstance(job.source_input, dict) else {}
    return {
        "format": str(job.format or ""),
        "confidence": _float(job.confidence),
        "damage_flags": list(job.damage_flags or []),
        "damage_flag_count": len(job.damage_flags or []),
        "attempts": _int(job.attempts),
        "has_password": job.password is not None,
        "source_kind": str(source.get("kind") or source.get("open_mode") or ""),
        "source_format_hint": str(source.get("format_hint") or source.get("format") or ""),
        "has_archive_state": archive_state is not None,
        "archive_state_size": _int(getattr(archive_state, "size", 0) if archive_state else 0),
        "archive_state_patch_count": len(getattr(archive_state, "patches", "") or ""),
    }


# ── Candidate proposal (unchanged from original) ────────────────────

def _candidate_proposal(payload: dict[str, Any], *, job: RepairJob | None = None, runtime_state_summary: dict[str, Any] | None = None) -> dict[str, Any]:
    output = {
        key: payload.get(key)
        for key in (
            "module",
            "format",
            "stage",
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
        )
        if key in payload
    }
    if str(output.get("plan_kind") or "") == "materialized":
        output.pop("plan_kind", None)
    for group, safe_names in _SAFE_BREAKDOWNS.items():
        breakdown = payload.get(group)
        if isinstance(breakdown, dict):
            safe = _safe_breakdown(breakdown, safe_names)
            if safe:
                output[group] = safe
    ltr = payload.get("ltr_features")
    if isinstance(ltr, dict):
        output["proposal_ltr"] = {
            key: ltr.get(key)
            for key in (
                "confidence",
                "score_hint",
                "patch_cost",
                "patch_quality",
                "partial",
                "lazy",
                "requires_native_validation",
                "requires_materialization",
                "plan_kind",
                "estimated_cost",
                "has_archive_state_plan",
                "damage_flag_count",
                "action_count",
                "history_available",
                "history_sample_count",
                "history_score",
            )
            if key in ltr
        }
        if str(output["proposal_ltr"].get("plan_kind") or "") == "materialized":
            output["proposal_ltr"].pop("plan_kind", None)
    output.update(_zip_plan_risk_features(payload, job=job, runtime_state_summary=runtime_state_summary or {}))
    return output


def _zip_plan_risk_features(payload: dict[str, Any], *, job: RepairJob | None, runtime_state_summary: dict[str, Any]) -> dict[str, Any]:
    module = str(payload.get("module") or "").lower()
    actions = [str(action).lower() for action in payload.get("actions") or []]
    text = " ".join([module, *actions])
    hints = _repair_hints(job) if job is not None else {}
    raw_damage_flags = payload.get("damage_flags") or (getattr(job, "damage_flags", None) if job is not None else None) or []
    damage_flags = {str(flag).lower() for flag in raw_damage_flags}
    context_flags = {str(flag).lower() for flag in runtime_state_summary.get("damage_flags") or []}
    all_flags = damage_flags | context_flags
    directory_detected = bool(runtime_state_summary.get("directory_detected"))
    entry_count = _int(runtime_state_summary.get("entry_count"))
    boundary_untrusted = bool(hints.get("boundary_untrusted")) or "boundary_unreliable" in all_flags or "trailing_junk" in all_flags
    likely_payload_damage = bool(hints.get("likely_payload_damage")) or "payload_damage" in all_flags or "crc_error" in all_flags or "checksum_error" in all_flags

    requires_existing_cd = any(token in text for token in ("comment_length", "central_directory_offset", "central_directory_count", "data_descriptor"))
    requires_valid_eocd = any(token in text for token in ("eocd", "comment_length", "central_directory_offset", "central_directory_count"))
    uses_data_descriptor = "data_descriptor" in text or "descriptor" in text
    touches_payload = any(token in text for token in ("payload", "partial", "deep", "quarantine", "descriptor"))
    directory_rewrite = any(token in text for token in ("central_directory", "directory", "eocd", "rebuild", "comment_length"))
    boundary_trim = any(token in text for token in ("trim", "trailing", "boundary"))

    expected_output_kind = "generic"
    if boundary_trim:
        expected_output_kind = "boundary_trim"
    elif "quarantine" in text:
        expected_output_kind = "partial_quarantine"
    elif "partial" in text or "deep" in text:
        expected_output_kind = "partial_deep"
    elif directory_rewrite:
        expected_output_kind = "directory_repair"
    elif uses_data_descriptor:
        expected_output_kind = "descriptor_recovery"

    directory_confidence = 0.0
    if directory_detected:
        directory_confidence += 0.55
    if entry_count > 0:
        directory_confidence += 0.25
    if requires_valid_eocd and boundary_untrusted:
        directory_confidence -= 0.25
    if "missing_directory" in all_flags or "central_directory_damaged" in all_flags:
        directory_confidence -= 0.20
    directory_confidence = _clamp01(directory_confidence)

    offset_confidence = 0.45
    if directory_detected:
        offset_confidence += 0.20
    if boundary_untrusted:
        offset_confidence -= 0.20
    if "offset" in text:
        offset_confidence -= 0.10
    offset_confidence = _clamp01(offset_confidence)

    risk = 0.0
    if requires_existing_cd and not directory_detected:
        risk += 0.28
    if requires_valid_eocd and boundary_untrusted:
        risk += 0.18
    if uses_data_descriptor and entry_count <= 0:
        risk += 0.20
    if touches_payload and likely_payload_damage:
        risk += 0.18
    if boundary_trim and not boundary_untrusted:
        risk += 0.12
    if "comment_length" in text:
        risk += 0.08
    no_output_risk_score = _clamp01(risk)

    return {
        "plan_requires_existing_cd": requires_existing_cd,
        "plan_requires_valid_eocd": requires_valid_eocd,
        "plan_uses_data_descriptor": uses_data_descriptor,
        "plan_touches_payload": touches_payload,
        "plan_expected_output_kind": expected_output_kind,
        "plan_directory_rewrite": directory_rewrite,
        "plan_boundary_trim": boundary_trim,
        "offset_confidence": offset_confidence,
        "directory_confidence": directory_confidence,
        "no_output_prone_candidate": no_output_risk_score >= 0.35,
        "no_output_risk_score": no_output_risk_score,
    }


# ── Native feedback ─────────────────────────────────────────────────

def _native_feedback(candidate: Any) -> dict[str, Any]:
    """Extract native diagnostics from candidate's diagnosis dict."""
    diagnosis = getattr(candidate, "diagnosis", None) if candidate is not None else None
    if not isinstance(diagnosis, dict):
        diagnosis = {}

    _NATIVE_KEYS = (
        "native_zip_deep_recovery",
        "native_zip_directory_field_repair",
        "native_zip_rebuild",
        "native_zip_conflict_resolver",
        "native_zip_verified_entry_salvage",
        "native_zip_cd_local_header_reconcile",
        "native_zip_salvage_deep",
        "native_zip_salvage_reconcile",
        "native_zip_salvage_quarantine",
        "native_zip_entry_quarantine",
        "native_zip_resolve_conflicts",
    )
    for key in _NATIVE_KEYS:
        native = diagnosis.get(key)
        if isinstance(native, dict):
            diag = native.get("diagnostics") or native.get("diagnostic")
            if isinstance(diag, dict):
                return dict(diag)
    return {}


# ── Repair prior payload ───────────────────────────────────────────

def _repair_prior_payload(repair_prior: RepairPrior | dict[str, Any] | None, payload: dict[str, Any]) -> dict[str, Any]:
    if repair_prior is None:
        prior = RepairPrior()
    elif isinstance(repair_prior, RepairPrior):
        prior = repair_prior
    else:
        prior = RepairPrior(
            route_score=repair_prior.get("route_score"),
            fine_score=repair_prior.get("fine_score"),
            generation_priority=repair_prior.get("generation_priority"),
            current_selector_rank=repair_prior.get("current_selector_rank"),
            module_selected_by_router=repair_prior.get("module_selected_by_router"),
            proposal_breakdowns=dict(repair_prior.get("proposal_breakdowns") or {}),
        )
    return {
        "route_score": _optional_float(prior.route_score),
        "fine_score": _optional_float(prior.fine_score),
        "generation_priority": _optional_float(prior.generation_priority if prior.generation_priority is not None else payload.get("generation_priority")),
        "current_selector_rank": _optional_int(prior.current_selector_rank),
        "module_selected_by_router": prior.module_selected_by_router,
        "proposal_breakdowns": prior.proposal_breakdowns or {
            group: _safe_breakdown(payload.get(group) if isinstance(payload.get(group), dict) else {}, names)
            for group, names in _SAFE_BREAKDOWNS.items()
        },
    }


_SAFE_BREAKDOWNS = {
    "benefit_breakdown": {"confidence", "score_hint"},
    "evidence_breakdown": {"patch_quality"},
    "cost_breakdown": {"stage", "lazy_materialization", "native_validation", "patch_complexity"},
    "risk_breakdown": {
        "partial_candidate",
        "content_damage",
        "content_damage_without_native_validation",
        "deep_without_native_validation",
    },
}


def _safe_breakdown(breakdown: dict[str, Any], safe_names: set[str]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for key, value in breakdown.items():
        if key not in safe_names or not isinstance(value, dict):
            continue
        output[key] = {
            inner_key: inner_value
            for inner_key, inner_value in value.items()
            if inner_key in {"value", "weight", "contribution"}
        }
    return output


# ── Utility helpers ─────────────────────────────────────────────────

def _float(value: Any, *, default: float = 0.0) -> float:
    try:
        if value is None:
            return float(default)
        return float(value)
    except Exception:
        return float(default)


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value or 0.0)))


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return _float(value)


def _int(value: Any) -> int:
    try:
        if value is None:
            return 0
        return int(value)
    except Exception:
        return 0


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return _int(value)


def _safe_feature_value(value: Any) -> Any:
    """Convert a value to a type safe for feature extraction (no dicts/lists)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return len(value)  # just count
    if isinstance(value, dict):
        return len(value)
    if value is None:
        return 0
    return str(value)[:100]  # truncate long strings
