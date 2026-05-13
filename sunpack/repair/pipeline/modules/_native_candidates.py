from __future__ import annotations

from typing import Any

from sunpack.contracts.archive_state import PatchPlan
from sunpack.repair.candidate import CandidateValidation, RepairCandidate
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.modules._common import crop_source_input_ranges, patched_state_for_job, patch_diagnosis, source_input_for_job, virtual_patch_repaired_input


def candidates_from_native_result(
    module_name: str,
    result: dict[str, Any],
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    *,
    native_key: str,
    format_hint: str | None = None,
    partial_default: bool = False,
    allowed_statuses: tuple[str, ...] = ("repaired", "partial"),
    default_confidence: float = 0.7,
    default_message: str = "native repair produced a candidate",
    prefer_patch_plan: bool = False,
    repair_name: str | None = None,
    atomic_action_group: str | None = None,
) -> list[RepairCandidate]:
    status = str(result.get("status") or "unrepairable")
    if status not in allowed_statuses:
        return []
    if bool(result.get("native_target_mismatch")):
        return []
    fmt = str(result.get("format") or format_hint or diagnosis.format or job.format or "archive")
    raw_candidates = result.get("candidates") if isinstance(result.get("candidates"), list) else []
    selected_path = str(result.get("selected_path") or "")
    if not raw_candidates and selected_path:
        raw_candidates = [{
            "name": result.get("selected_candidate") or "selected",
            "path": selected_path,
            "status": status,
            "confidence": result.get("confidence", default_confidence),
            "actions": list(result.get("actions") or []),
        }]

    candidates: list[RepairCandidate] = []
    runtime_source_input = source_input_for_job(job)
    for index, raw in enumerate(raw_candidates):
        item = _candidate_mapping(raw, index)
        path = str(item.get("path") or "")
        patch_plan = _patch_plan_from_item(item)
        use_patch_plan = bool(prefer_patch_plan and patch_plan is not None)
        if not path and not use_patch_plan:
            continue
        item_status = str(item.get("status") or status)
        confidence = float(item.get("confidence", result.get("confidence", default_confidence)) or 0.0)
        actions = list(item.get("actions") or result.get("actions") or [])
        warnings = _dedupe([*list(result.get("warnings") or []), *list(item.get("warnings") or [])])
        workspace_paths = [] if use_patch_plan else _dedupe([path, *[str(value) for value in result.get("workspace_paths") or []]])
        candidate_format = str(item.get("format") or fmt)
        details = {
            key: value
            for key, value in item.items()
            if key not in {"path", "actions", "warnings", "patch_plan"}
        }
        repaired_input = {"kind": "file", "path": path, "format_hint": candidate_format}
        plan: dict[str, Any] = {}
        diagnosis_payload: dict[str, Any] = {
            **diagnosis.as_dict(),
            "repair_name": str(repair_name or item.get("name") or module_name),
            "native_key": native_key,
            "native_target": str(item.get("native_target") or result.get("native_target") or ""),
            "candidate_status": str(item.get("candidate_status") or result.get("candidate_status") or ""),
            "atomic_action_group": str(atomic_action_group or repair_name or module_name),
            "patch_facts": _dedupe([str(value) for value in item.get("patch_facts") or result.get("patch_facts") or []]),
            "residual_facts": _dedupe([str(value) for value in item.get("residual_facts") or result.get("residual_facts") or []]),
            "validation_details": dict(item.get("validation_details") or result.get("validation_details") or {}),
            "logical_stream_built": bool(runtime_source_input.get("logical_stream_built")) or str(runtime_source_input.get("kind") or "") == "concat_ranges",
            "native_target_mismatch": bool(item.get("native_target_mismatch") or result.get("native_target_mismatch")),
            native_key: dict(result),
            "native_candidate": {"index": index, **details},
        }
        split_crop_input = _split_aware_crop_repaired_input(item, result, job, runtime_source_input, candidate_format)
        if split_crop_input is not None:
            repaired_input = split_crop_input
            facts = [str(value) for value in diagnosis_payload.get("patch_facts") or []]
            facts.append("split_logical_stream_preserved_after_crop")
            diagnosis_payload["patch_facts"] = _dedupe(facts)
        validation_details = diagnosis_payload["validation_details"]
        if isinstance(validation_details, dict):
            policy = str(validation_details.get("policy") or item.get("policy") or "")
            if policy:
                facts = [str(value) for value in diagnosis_payload.get("patch_facts") or []]
                facts.append(f"kept_entry_policy={policy}")
                diagnosis_payload["patch_facts"] = _dedupe(facts)
            for key in (
                "duplicate_group_count",
                "kept_entry_crc_match_count",
                "kept_payload_verified_count",
                "dropped_entry_count",
                "ambiguous_duplicate_group_count",
            ):
                if key not in validation_details and key in item:
                    validation_details[key] = item.get(key)
            if policy:
                validation_details.setdefault("duplicate_group_count", 0)
                validation_details.setdefault("kept_entry_crc_match_count", validation_details.get("crc_match_count", 0) or 0)
                validation_details.setdefault("kept_payload_verified_count", 0)
                validation_details.setdefault("dropped_entry_count", validation_details.get("dropped_entries", 0) or 0)
                validation_details.setdefault("ambiguous_duplicate_group_count", 0)
            diagnosis_payload["validation_details"] = validation_details
        requires_native_validation = True
        if use_patch_plan and patch_plan is not None:
            repaired_state = patched_state_for_job(job, patch_plan)
            repaired_input = virtual_patch_repaired_input(repaired_state)
            plan = {
                "patch_plan": patch_plan.to_dict(),
                "archive_state": repaired_state.to_dict(),
            }
            diagnosis_payload = patch_diagnosis(diagnosis_payload, patch_plan, repaired_state)
            requires_native_validation = False
        if job.password is not None:
            repaired_input["password"] = job.password
        candidates.append(RepairCandidate(
            module_name=module_name,
            format=candidate_format,
            repaired_input=repaired_input,
            status="partial" if partial_default else (item_status if item_status in {"repaired", "partial"} else status),
            stage="deep",
            confidence=confidence,
            partial=bool(partial_default or item_status == "partial" or status == "partial"),
            requires_native_validation=requires_native_validation,
            actions=actions,
            damage_flags=list(job.damage_flags),
            warnings=warnings,
            workspace_paths=workspace_paths,
            diagnosis=diagnosis_payload,
            message=str(result.get("message") or default_message),
            validations=[
                CandidateValidation(
                    name="native_candidate",
                    accepted=True,
                    score=confidence,
                    details={"index": index, **details},
                )
            ],
            plan=plan,
        ))
    return candidates


def _split_aware_crop_repaired_input(
    item: dict[str, Any],
    result: dict[str, Any],
    job: RepairJob,
    runtime_source_input: dict[str, Any],
    candidate_format: str,
) -> dict[str, Any] | None:
    facts = {str(value) for value in item.get("patch_facts") or result.get("patch_facts") or []}
    actions = {str(value) for value in item.get("actions") or result.get("actions") or []}
    if "after_archive_carrier_crop" not in facts and "crop_archive_carrier_prefix" not in actions:
        return None
    source_input = dict(getattr(job, "source_input", None) or {})
    if str(source_input.get("kind") or "") != "concat_ranges" and not source_input.get("parts"):
        source_input = dict(runtime_source_input or {})
    if str(source_input.get("kind") or "") != "concat_ranges" and not source_input.get("parts"):
        return None
    try:
        start = int(item.get("offset") if item.get("offset") is not None else item.get("cropped_start") or 0)
    except (TypeError, ValueError):
        return None
    end = _crop_end(item, result)
    if _is_split_logical_source(source_input):
        target = str(item.get("native_target") or result.get("native_target") or "")
        is_prefix_crop = (
            "crop_archive_carrier_prefix" in actions
            or "crop_7z_carrier_prefix" in actions
            or "after_archive_carrier_crop" in facts
            or target in {"archive_carrier_crop", "carrier_prefix"}
        )
        if is_prefix_crop:
            end = None
    repaired = crop_source_input_ranges(source_input, start, end)
    if repaired is None:
        return None
    repaired["format_hint"] = candidate_format
    if job.password is not None:
        repaired["password"] = job.password
    return repaired


def _is_split_logical_source(source_input: dict[str, Any]) -> bool:
    if bool(source_input.get("split_sidecars_available")) or bool(source_input.get("logical_stream_built")):
        return True
    if isinstance(source_input.get("parts"), list) and len(source_input.get("parts") or []) > 1:
        return True
    if str(source_input.get("kind") or "") == "concat_ranges" and len(source_input.get("ranges") or []) > 1:
        return True
    return False


def _crop_end(item: dict[str, Any], result: dict[str, Any]) -> int | None:
    for key in ("end_offset", "cropped_end"):
        value = item.get(key)
        if value is None:
            continue
        try:
            end = int(value)
        except (TypeError, ValueError):
            continue
        if end > 0:
            return end
    return None


def _candidate_mapping(raw: Any, index: int) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        return {"name": f"candidate_{index}", "path": raw}
    return {}


def _patch_plan_from_item(item: dict[str, Any]) -> PatchPlan | None:
    raw = item.get("patch_plan")
    if not isinstance(raw, dict):
        return None
    try:
        return PatchPlan.from_dict(raw)
    except (TypeError, ValueError):
        return None


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output
