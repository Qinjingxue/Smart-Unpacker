from __future__ import annotations

from typing import Any

from smart_unpacker.contracts.archive_state import PatchPlan
from smart_unpacker.repair.candidate import CandidateValidation, RepairCandidate
from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.modules._common import patched_state_for_job, patch_diagnosis, virtual_patch_repaired_input


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
) -> list[RepairCandidate]:
    status = str(result.get("status") or "unrepairable")
    if status not in allowed_statuses:
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
            native_key: dict(result),
            "native_candidate": {"index": index, **details},
        }
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
            status=item_status if item_status in {"repaired", "partial"} else status,
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
