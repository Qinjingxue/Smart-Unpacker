from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from packrelic.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from packrelic.repair.job import RepairJob
from packrelic.repair.result import RepairResult
from packrelic.support.archive_state_view import archive_state_from_source_input, archive_state_to_bytes

from packrelic_native import (
    repair_concat_ranges_to_bytes as _native_concat_ranges_to_bytes,
    repair_concat_ranges_to_file as _native_concat_ranges_to_file,
    repair_copy_range_to_file as _native_copy_range_to_file,
    repair_patch_file as _native_patch_file,
    repair_read_file_range as _native_read_file_range,
    repair_write_candidate as _native_write_candidate,
)


def load_source_bytes(source_input: dict[str, Any]) -> bytes:
    kind = str(source_input.get("kind") or "file")
    if kind in {"bytes", "memory"}:
        data = source_input.get("data", b"")
        if isinstance(data, bytes):
            return bytes(data)
        if isinstance(data, bytearray):
            return bytes(data)
        raise ValueError("bytes repair input requires a bytes payload")
    if kind == "file":
        return bytes(_native_read_file_range(str(source_input["path"]), 0, None))
    if kind == "file_range":
        path = str(source_input["path"])
        start = int(source_input.get("start") or 0)
        end = source_input.get("end")
        end_int = None if end is None else int(end)
        return bytes(_native_read_file_range(path, start, end_int))
    if kind == "concat_ranges":
        ranges = list(source_input.get("ranges") or [])
        return bytes(_native_concat_ranges_to_bytes(ranges))
    raise ValueError(f"unsupported repair input kind: {kind}")


def source_input_for_job(job: RepairJob) -> dict[str, Any]:
    if job.archive_state is None or not job.archive_state.patches:
        return dict(job.source_input)
    return {
        "kind": "bytes",
        "data": archive_state_to_bytes(job.archive_state),
        "format_hint": job.archive_state.format_hint or job.archive_state.source.format_hint or job.format,
        "patch_digest": job.archive_state.effective_patch_digest(),
    }


def job_source_size(job: RepairJob) -> int | None:
    if job.archive_state is not None and job.archive_state.patches:
        try:
            from packrelic.support.archive_state_view import ArchiveStateByteView

            return int(ArchiveStateByteView(job.archive_state).size)
        except (OSError, ValueError):
            return None
    return source_input_size(job.source_input)


def base_archive_state_for_job(job: RepairJob) -> ArchiveState:
    if job.archive_state is not None:
        return job.archive_state
    return archive_state_from_source_input(
        job.source_input,
        format_hint=job.format,
        logical_name=str(job.archive_key or ""),
    )


def patch_plan_for_byte_patches(
    job: RepairJob,
    module_name: str,
    patches: list[dict[str, Any]],
    *,
    confidence: float,
    actions: list[str],
) -> PatchPlan:
    operations = [
        PatchOperation.replace_bytes(
            offset=int(patch["offset"]),
            data=bytes(patch["data"]),
            details={"module": module_name},
        )
        for patch in patches
    ]
    return PatchPlan(
        operations=operations,
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base_archive_state_for_job(job).effective_patch_digest()},
        confidence=float(confidence),
    )


def patch_plan_for_insert(
    job: RepairJob,
    module_name: str,
    offset: int,
    data: bytes,
    *,
    confidence: float,
    actions: list[str],
) -> PatchPlan:
    return PatchPlan(
        operations=[
            PatchOperation(
                op="insert",
                offset=int(offset),
                size=len(data),
                data_b64=base64.b64encode(bytes(data)).decode("ascii"),
                details={"module": module_name},
            )
        ],
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base_archive_state_for_job(job).effective_patch_digest()},
        confidence=float(confidence),
    )


def patch_plan_for_truncate(job: RepairJob, module_name: str, size: int, *, confidence: float, actions: list[str]) -> PatchPlan:
    return PatchPlan(
        operations=[PatchOperation(op="truncate", offset=int(size), size=0, details={"module": module_name})],
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base_archive_state_for_job(job).effective_patch_digest()},
        confidence=float(confidence),
    )


def patch_plan_for_truncate_append(
    job: RepairJob,
    module_name: str,
    size: int,
    data: bytes,
    *,
    confidence: float,
    actions: list[str],
) -> PatchPlan:
    return PatchPlan(
        operations=[
            PatchOperation(op="truncate", offset=int(size), size=0, details={"module": module_name}),
            PatchOperation.append_bytes(bytes(data), details={"module": module_name}),
        ],
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base_archive_state_for_job(job).effective_patch_digest()},
        confidence=float(confidence),
    )


def patch_plan_for_crop(
    job: RepairJob,
    module_name: str,
    start: int,
    end: int,
    *,
    confidence: float,
    actions: list[str],
) -> PatchPlan:
    start = max(0, int(start))
    end = max(start, int(end))
    operations: list[PatchOperation] = []
    if start:
        operations.append(PatchOperation.delete_range(offset=0, size=start, details={"module": module_name}))
    operations.append(PatchOperation(op="truncate", offset=end - start, size=0, details={"module": module_name}))
    return PatchPlan(
        operations=operations,
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base_archive_state_for_job(job).effective_patch_digest(), "crop_start": start, "crop_end": end},
        confidence=float(confidence),
    )


def patch_plan_for_crop_append(
    job: RepairJob,
    module_name: str,
    start: int,
    end: int,
    data: bytes,
    *,
    confidence: float,
    actions: list[str],
) -> PatchPlan:
    start = max(0, int(start))
    end = max(start, int(end))
    operations: list[PatchOperation] = []
    if start:
        operations.append(PatchOperation.delete_range(offset=0, size=start, details={"module": module_name}))
    operations.extend([
        PatchOperation(op="truncate", offset=end - start, size=0, details={"module": module_name}),
        PatchOperation.append_bytes(bytes(data), details={"module": module_name}),
    ])
    return PatchPlan(
        operations=operations,
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base_archive_state_for_job(job).effective_patch_digest(), "crop_start": start, "crop_end": end},
        confidence=float(confidence),
    )


def patched_state_for_job(job: RepairJob, patch_plan: PatchPlan) -> ArchiveState:
    base = base_archive_state_for_job(job)
    return ArchiveState(
        source=base.source,
        patches=[*base.patches, patch_plan],
        patch_digest="",
        logical_name=base.logical_name,
        format_hint=base.format_hint or job.format,
        analysis=dict(base.analysis),
        verification=dict(base.verification),
    )


def patch_diagnosis(diagnosis: dict[str, Any], patch_plan: PatchPlan, repaired_state: ArchiveState) -> dict[str, Any]:
    return {
        **diagnosis,
        "patch_plan": patch_plan.to_dict(),
        "archive_state": repaired_state.to_dict(),
    }


def virtual_patch_repaired_input(repaired_state: ArchiveState) -> dict[str, Any]:
    return {
        "kind": "archive_state",
        "patch_digest": repaired_state.effective_patch_digest(),
        "format_hint": repaired_state.format_hint or repaired_state.source.format_hint,
    }


def should_materialize_candidate(config: dict[str, Any]) -> bool:
    return not bool(config.get("virtual_patch_candidate", False))


def patch_repair_result(
    *,
    job: RepairJob,
    diagnosis,
    module_name: str,
    fmt: str,
    patch_plan: PatchPlan,
    confidence: float,
    actions: list[str],
    workspace: str,
    filename: str,
    config: dict[str, Any],
    materialized_data: bytes | None = None,
    status: str = "repaired",
    warnings: list[str] | None = None,
    partial: bool = False,
    message: str = "",
) -> RepairResult:
    repaired_state = patched_state_for_job(job, patch_plan)
    path = ""
    if should_materialize_candidate(config):
        data = materialized_data if materialized_data is not None else archive_state_to_bytes(repaired_state)
        path = write_candidate(bytes(data), workspace, filename)
        repaired_input = {"kind": "file", "path": path, "format_hint": fmt}
    else:
        repaired_input = virtual_patch_repaired_input(repaired_state)
    if job.password is not None:
        repaired_input["password"] = job.password
    diagnosis_payload = diagnosis.as_dict() if hasattr(diagnosis, "as_dict") else dict(diagnosis or {})
    return RepairResult(
        status=status,  # type: ignore[arg-type]
        confidence=float(confidence or 0.0),
        format=fmt,
        repaired_input=repaired_input,
        actions=list(actions),
        damage_flags=list(job.damage_flags),
        warnings=list(warnings or []),
        workspace_paths=[path] if path else [],
        partial=bool(partial),
        module_name=module_name,
        diagnosis=patch_diagnosis(diagnosis_payload, patch_plan, repaired_state),
        message=message,
        repaired_state=repaired_state,
    )


def write_candidate(data: bytes, workspace: str, filename: str) -> str:
    return str(_native_write_candidate(data, workspace, filename))


def copy_range_to_file(source_path: str, start: int, end: int | None, output_path: str) -> str:
    return str(_native_copy_range_to_file(source_path, int(start), None if end is None else int(end), output_path))


def concat_ranges_to_file(ranges: list[dict[str, Any]], output_path: str) -> str:
    return str(_native_concat_ranges_to_file(ranges, output_path))


def patch_file(source_path: str, patches: list[dict[str, Any]], output_path: str) -> str:
    return str(_native_patch_file(source_path, patches, output_path))


def copy_source_prefix_to_file(source_input: dict[str, Any], length: int, output_path: str) -> str:
    length = max(0, int(length))
    kind = str(source_input.get("kind") or "file")
    if kind in {"bytes", "memory"}:
        data = load_source_bytes(source_input)[:length]
        return write_candidate(data, str(Path(output_path).parent), Path(output_path).name)
    if kind == "file":
        return copy_range_to_file(str(source_input["path"]), 0, length, output_path)
    if kind == "file_range":
        start = int(source_input.get("start") or 0)
        declared_end = source_input.get("end")
        end = start + length
        if declared_end is not None:
            end = min(end, int(declared_end))
        return copy_range_to_file(str(source_input["path"]), start, end, output_path)
    if kind == "concat_ranges":
        ranges = _take_concat_prefix(list(source_input.get("ranges") or []), length)
        return concat_ranges_to_file(ranges, output_path)
    raise ValueError(f"unsupported repair input kind: {kind}")


def source_input_size(source_input: dict[str, Any]) -> int | None:
    kind = str(source_input.get("kind") or "file")
    if kind in {"bytes", "memory"}:
        try:
            return len(load_source_bytes(source_input))
        except ValueError:
            return None
    if kind == "file":
        return _path_size(source_input.get("path"))
    if kind == "file_range":
        return _range_size(source_input)
    if kind == "concat_ranges":
        total = 0
        for item in source_input.get("ranges") or []:
            if not isinstance(item, dict):
                return None
            size = _range_size(item)
            if size is None:
                return None
            total += size
        return total
    return None


def _take_concat_prefix(ranges: list[dict[str, Any]], length: int) -> list[dict[str, Any]]:
    result = []
    remaining = length
    for item in ranges:
        if remaining <= 0:
            break
        start = int(item.get("start") or 0)
        end = item.get("end")
        if end is None:
            take_end = start + remaining
        else:
            available = max(0, int(end) - start)
            take_end = start + min(available, remaining)
        if take_end > start:
            result.append({**item, "start": start, "end": take_end})
            remaining -= take_end - start
    return result


def _range_size(item: dict[str, Any]) -> int | None:
    start = int(item.get("start") or 0)
    end = item.get("end")
    if end is not None:
        return max(0, int(end) - start)
    size = _path_size(item.get("path"))
    if size is None:
        return None
    return max(0, size - start)


def _path_size(path: Any) -> int | None:
    try:
        return Path(str(path)).stat().st_size
    except (OSError, TypeError, ValueError):
        return None
