from __future__ import annotations

from typing import Any

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.modules._common import (
    patch_diagnosis,
    patch_plan_for_byte_patches,
    patch_plan_for_truncate,
    patch_plan_for_truncate_append,
    patched_state_for_job,
    should_materialize_candidate,
    virtual_patch_repaired_input,
)
from packrelic.repair.result import RepairResult


def native_patch_repair_result(
    *,
    module_name: str,
    fmt: str,
    native_key: str,
    result: dict[str, Any],
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    config: dict,
    partial: bool = False,
) -> RepairResult:
    status = str(result.get("status") or "unrepairable")
    if status not in {"repaired", "partial"}:
        return RepairResult(
            status="unrepairable" if status in {"skipped", "unsupported"} else status,
            confidence=float(result.get("confidence") or 0.0),
            format=fmt,
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            module_name=module_name,
            diagnosis={**diagnosis.as_dict(), native_key: dict(result)},
            message=str(result.get("message") or "native repair did not produce a candidate"),
        )

    actions = list(result.get("actions") or [])
    confidence = float(result.get("confidence") or 0.0)
    patches = [
        {"offset": int(item.get("offset") or 0), "data": bytes(item.get("data") or b"")}
        for item in result.get("patches") or []
        if isinstance(item, dict)
    ]
    truncate_at = result.get("truncate_at")
    append_data = result.get("append_data")
    if truncate_at is not None and append_data is not None:
        patch_plan = patch_plan_for_truncate_append(
            job,
            module_name,
            int(truncate_at),
            bytes(append_data),
            confidence=confidence,
            actions=actions,
        )
    elif truncate_at is not None:
        patch_plan = patch_plan_for_truncate(
            job,
            module_name,
            int(truncate_at),
            confidence=confidence,
            actions=actions,
        )
    else:
        patch_plan = patch_plan_for_byte_patches(job, module_name, patches, confidence=confidence, actions=actions)

    repaired_state = patched_state_for_job(job, patch_plan)
    selected_path = str(result.get("selected_path") or "")
    if should_materialize_candidate(config):
        repaired_input = {"kind": "file", "path": selected_path, "format_hint": fmt}
        workspace_paths = list(result.get("workspace_paths") or ([selected_path] if selected_path else []))
    else:
        repaired_input = virtual_patch_repaired_input(repaired_state)
        workspace_paths = []
    return RepairResult(
        status=status,
        confidence=confidence,
        format=fmt,
        repaired_input=repaired_input,
        actions=actions,
        damage_flags=list(job.damage_flags),
        warnings=list(result.get("warnings") or []),
        workspace_paths=workspace_paths,
        partial=partial or status == "partial",
        module_name=module_name,
        diagnosis=patch_diagnosis({**diagnosis.as_dict(), native_key: dict(result)}, patch_plan, repaired_state),
        repaired_state=repaired_state,
        message=str(result.get("message") or "native repair produced a candidate"),
    )
