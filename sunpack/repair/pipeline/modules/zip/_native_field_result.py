from __future__ import annotations

from typing import Any

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.modules._common import (
    patch_diagnosis,
    patch_plan_for_byte_patches,
    patch_plan_for_truncate,
    patch_plan_for_truncate_append,
    patched_state_for_job,
    should_materialize_candidate,
    virtual_patch_repaired_input,
)
from sunpack.repair.result import RepairResult


def repair_result_from_native_zip_field(
    module_name: str,
    result: dict[str, Any],
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    config: dict,
    *,
    repair_name: str | None = None,
    atomic_action_group: str | None = None,
) -> RepairResult:
    repair_meta = _repair_meta(module_name, repair_name, atomic_action_group, "native_zip_directory_field_repair")
    native_meta = _native_meta(result)
    status = str(result.get("status") or "unrepairable")
    if status != "repaired":
        return RepairResult(
            status="unrepairable" if status in {"skipped", "unsupported"} else status,
            confidence=float(result.get("confidence") or 0.0),
            format="zip",
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            module_name=module_name,
            diagnosis={**diagnosis.as_dict(), **repair_meta, **native_meta, "native_zip_directory_field_repair": dict(result)},
            message=str(result.get("message") or "native ZIP field repair did not produce a candidate"),
        )

    patches = [
        {"offset": int(item.get("offset") or 0), "data": bytes(item.get("data") or b"")}
        for item in result.get("patches") or []
        if isinstance(item, dict)
    ]
    actions = list(result.get("actions") or [])
    confidence = float(result.get("confidence") or 0.0)
    payload_damage_flags = {
        "checksum_error",
        "crc_error",
        "damaged",
        "entry_payload_bad",
        "payload_bad",
        "data_error",
    }
    partial = bool(set(job.damage_flags) & payload_damage_flags)
    if result.get("truncate_at") is not None:
        if patches:
            patch_plan = patch_plan_for_truncate_append(
                job,
                module_name,
                int(result.get("truncate_at") or 0),
                bytes(patches[0]["data"]),
                confidence=confidence,
                actions=actions,
            )
        else:
            patch_plan = patch_plan_for_truncate(
                job,
                module_name,
                int(result.get("truncate_at") or 0),
                confidence=confidence,
                actions=actions,
            )
    else:
        patch_plan = patch_plan_for_byte_patches(job, module_name, patches, confidence=confidence, actions=actions)
    repaired_state = patched_state_for_job(job, patch_plan)
    selected_path = str(result.get("selected_path") or "")
    if should_materialize_candidate(config, "zip"):
        repaired_input = {"kind": "file", "path": selected_path, "format_hint": "zip"}
        workspace_paths = list(result.get("workspace_paths") or ([selected_path] if selected_path else []))
    else:
        selected_path = ""
        repaired_input = virtual_patch_repaired_input(repaired_state)
        workspace_paths = []
    return RepairResult(
        status="partial" if partial else "repaired",
        confidence=confidence,
        format="zip",
        repaired_input=repaired_input,
        actions=actions,
        damage_flags=list(job.damage_flags),
        warnings=list(result.get("warnings") or []),
        workspace_paths=workspace_paths,
        partial=partial,
        module_name=module_name,
        diagnosis=patch_diagnosis(
            {**diagnosis.as_dict(), **repair_meta, **native_meta, "native_zip_directory_field_repair": dict(result)},
            patch_plan,
            repaired_state,
        ),
        repaired_state=repaired_state,
        message=str(result.get("message") or "native ZIP field repair produced a candidate"),
    )


def _repair_meta(module_name: str, repair_name: str | None, atomic_action_group: str | None, native_key: str) -> dict[str, Any]:
    action = str(repair_name or module_name)
    return {
        "repair_name": action,
        "native_key": native_key,
        "atomic_action_group": str(atomic_action_group or action),
    }


def _native_meta(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "native_target": str(result.get("native_target") or ""),
        "candidate_status": str(result.get("candidate_status") or ""),
        "patch_facts": [str(value) for value in result.get("patch_facts") or []],
        "residual_facts": [str(value) for value in result.get("residual_facts") or []],
        "validation_details": dict(result.get("validation_details") or {}),
        "native_target_mismatch": bool(result.get("native_target_mismatch")),
    }
