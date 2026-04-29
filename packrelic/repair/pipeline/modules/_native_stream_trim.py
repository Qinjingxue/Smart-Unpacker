from __future__ import annotations

from typing import Any

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.modules._common import (
    patch_diagnosis,
    patch_plan_for_truncate,
    patched_state_for_job,
    should_materialize_candidate,
    source_input_for_job,
    virtual_patch_repaired_input,
)
from packrelic.repair.result import RepairResult
from packrelic_native import compression_stream_trailing_junk_trim as _native_stream_trim


def native_stream_trailing_trim_result(
    *,
    module_name: str,
    fmt: str,
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    workspace: str,
    config: dict,
) -> RepairResult:
    deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
    result = dict(_native_stream_trim(
        source_input_for_job(job),
        fmt,
        workspace,
        float(deep.get("max_input_size_mb", 512) or 0),
        int(deep.get("max_trailing_junk_probe_bytes", 1024 * 1024) or 1024 * 1024),
    ))
    status = str(result.get("status") or "unrepairable")
    if status != "repaired":
        return RepairResult(
            status="unrepairable" if status in {"skipped", "unsupported"} else status,
            confidence=float(result.get("confidence") or 0.0),
            format=fmt,
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            module_name=module_name,
            diagnosis={**diagnosis.as_dict(), "native_compression_stream_trim": result},
            message=str(result.get("message") or "native stream trim did not produce a candidate"),
        )

    actions = list(result.get("actions") or [])
    confidence = float(result.get("confidence") or 0.0)
    truncate_at = int(result.get("truncate_at") or 0)
    patch_plan = patch_plan_for_truncate(job, module_name, truncate_at, confidence=confidence, actions=actions)
    repaired_state = patched_state_for_job(job, patch_plan)
    selected_path = str(result.get("selected_path") or "")
    if should_materialize_candidate(config):
        repaired_input = {"kind": "file", "path": selected_path, "format_hint": fmt}
        workspace_paths = list(result.get("workspace_paths") or ([selected_path] if selected_path else []))
    else:
        repaired_input = virtual_patch_repaired_input(repaired_state)
        workspace_paths = []
    return RepairResult(
        status="repaired",
        confidence=confidence,
        format=fmt,
        repaired_input=repaired_input,
        actions=actions,
        damage_flags=list(job.damage_flags),
        warnings=list(result.get("warnings") or []),
        workspace_paths=workspace_paths,
        module_name=module_name,
        diagnosis=patch_diagnosis(
            {**diagnosis.as_dict(), "native_compression_stream_trim": result},
            patch_plan,
            repaired_state,
        ),
        repaired_state=repaired_state,
        message=str(result.get("message") or "native stream trim produced a candidate"),
    )
