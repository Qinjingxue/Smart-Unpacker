from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.repair.job import RepairJob
from sunpack.repair.result import RepairResult
from sunpack.repair.runtime_cache import stable_cache_key
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.archive_state_view import archive_state_from_source_input, archive_state_to_bytes

from sunpack_native import (
    repair_concat_ranges_to_bytes as _native_concat_ranges_to_bytes,
    repair_concat_ranges_to_file as _native_concat_ranges_to_file,
    repair_copy_range_to_file as _native_copy_range_to_file,
    repair_patch_file as _native_patch_file,
    repair_read_file_range as _native_read_file_range,
    repair_write_candidate as _native_write_candidate,
)

DEFAULT_MODULE_LIMITS = {
    "max_candidates_per_module": 3,
    "max_entries": 20000,
    "max_seconds_per_module": 30.0,
    "max_input_size_mb": 512,
    "max_output_size_mb": 2048,
    "max_entry_uncompressed_mb": 512,
    "verify_candidates": True,
    "max_stream_trim_probe_attempts": 32,
    "max_stream_trim_decode_mb": 64,
    "max_gzip_footer_fix_decode_mb": 32,
    "max_next_header_scan_bytes": 1024 * 1024,
}


def module_limits(config: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict(DEFAULT_MODULE_LIMITS)
    if isinstance(config, dict):
        raw = config.get("module_limits")
        if isinstance(raw, dict):
            payload.update(raw)
    return payload


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
        base = dict(job.source_input)
    else:
        digest = job.archive_state.effective_patch_digest()
        cache = getattr(job, "repair_cache", None)
        if cache is not None:
            data = cache.get_or_compute(
                "archive_state_to_bytes",
                {
                    "patch_digest": digest,
                    "format_hint": job.archive_state.format_hint or job.archive_state.source.format_hint or job.format,
                },
                lambda: archive_state_to_bytes(job.archive_state),
            )
        else:
            data = archive_state_to_bytes(job.archive_state)
        base = {
            "kind": "bytes",
            "data": data,
            "format_hint": job.archive_state.format_hint or job.archive_state.source.format_hint or job.format,
            "patch_digest": digest,
        }
    if str(base.get("kind") or "") != "concat_ranges" and isinstance(base.get("parts"), list) and base.get("parts"):
        ranges: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in base.get("parts") or []:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or "")
            if not path or path in seen:
                continue
            seen.add(path)
            ranges.append({"path": path, "start": int(item.get("start") or 0), "end": item.get("end")})
        main_path = str(base.get("path") or "")
        if main_path and main_path not in seen and not bool(base.get("use_parts_only")):
            ranges.append({"path": main_path, "start": 0, "end": None})
        if ranges:
            base = {
                "kind": "concat_ranges",
                "ranges": ranges,
                "format_hint": base.get("format_hint") or job.format,
                "parts": base.get("parts"),
                "use_parts_only": bool(base.get("use_parts_only")),
                "split_sidecars_available": True,
                "logical_stream_built": True,
            }
    if str(base.get("kind") or "") == "concat_ranges":
        base["logical_stream_built"] = True
        if base.get("parts") or len(list(base.get("ranges") or [])) > 1:
            base["split_sidecars_available"] = True
    if str(base.get("kind") or "") == "concat_ranges" and getattr(job, "repair_cache", None) is not None and str(job.workspace or ""):
        fingerprint = source_fingerprint(base)
        workspace = Path(str(job.workspace)) / ".repair_cache"
        output_path = workspace / f"logical_{stable_cache_key(fingerprint)[:24]}.bin"
        def compute_concat_file() -> dict[str, str]:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            return {"path": concat_ranges_to_file(list(base.get("ranges") or []), str(output_path))}
        payload = job.repair_cache.get_or_compute(
            "concat_ranges_to_file",
            {"source": fingerprint, "output_path": str(output_path)},
            compute_concat_file,
        )
        path = str(payload.get("path") or output_path)
        if Path(path).is_file():
            base = {
                "kind": "file",
                "path": path,
                "format_hint": base.get("format_hint") or job.format,
                "parts": base.get("parts"),
                "use_parts_only": bool(base.get("use_parts_only")),
                "logical_stream_built": True,
                "split_sidecars_available": bool(base.get("split_sidecars_available")) or bool(base.get("parts")) or len(list(base.get("ranges") or [])) > 1,
            }
    if job.password:
        base["password"] = job.password
    return base


def repair_operation_cache_key(job: RepairJob, operation: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "source": source_fingerprint_for_job(job),
        "operation": str(operation),
        "params": _cache_jsonable(params or {}),
    }


def cached_repair_operation(job: RepairJob, namespace: str, operation: str, params: dict[str, Any], compute):
    cache = getattr(job, "repair_cache", None)
    if cache is None:
        return compute()
    return cache.get_or_compute(namespace, repair_operation_cache_key(job, operation, params), compute)


def source_fingerprint_for_job(job: RepairJob) -> dict[str, Any]:
    if isinstance(getattr(job, "knowledge", None), dict):
        markers = _repair_cache_markers(job.knowledge)
        cached = markers.get("source_fingerprint_for_job")
        if isinstance(cached, dict):
            return dict(cached)
    knowledge = ArchiveKnowledge.from_any(getattr(job, "knowledge", {}))
    fingerprint = knowledge_view.source_fingerprint(knowledge)
    if isinstance(getattr(job, "knowledge", None), dict):
        _repair_cache_markers(job.knowledge)["source_fingerprint_for_job"] = _cache_jsonable(fingerprint)
    return fingerprint


def _repair_cache_markers(payload: dict[str, Any]) -> dict[str, Any]:
    meta = payload.setdefault("_meta", {})
    if not isinstance(meta, dict):
        meta = {}
        payload["_meta"] = meta
    markers = meta.setdefault("repair_cache_markers", {})
    if not isinstance(markers, dict):
        markers = {}
        meta["repair_cache_markers"] = markers
    return markers


def source_fingerprint(source_input: dict[str, Any]) -> dict[str, Any]:
    kind = str(source_input.get("kind") or "file")
    if kind in {"bytes", "memory"}:
        data = source_input.get("data", b"")
        if isinstance(data, bytearray):
            data = bytes(data)
        if isinstance(data, bytes):
            return {"kind": kind, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "format_hint": source_input.get("format_hint")}
        return {"kind": kind, "data": str(data), "format_hint": source_input.get("format_hint")}
    if kind == "file":
        return {"kind": "file", **_path_fingerprint(str(source_input.get("path") or "")), "format_hint": source_input.get("format_hint")}
    if kind == "file_range":
        return {
            "kind": "file_range",
            **_path_fingerprint(str(source_input.get("path") or "")),
            "start": int(source_input.get("start") or 0),
            "end": source_input.get("end"),
            "format_hint": source_input.get("format_hint"),
        }
    if kind == "concat_ranges":
        ranges = []
        for item in source_input.get("ranges") or []:
            if not isinstance(item, dict):
                continue
            ranges.append({
                **_path_fingerprint(str(item.get("path") or "")),
                "start": int(item.get("start") or 0),
                "end": item.get("end"),
            })
        return {"kind": "concat_ranges", "ranges": ranges, "format_hint": source_input.get("format_hint")}
    return {"kind": kind, "payload": _cache_jsonable(source_input)}


def cache_relevant_module_limits(config: dict[str, Any] | None, keys: tuple[str, ...] = ()) -> dict[str, Any]:
    limits = module_limits(config)
    selected = keys or (
        "max_candidates_per_module",
        "max_entries",
        "max_seconds_per_module",
        "max_input_size_mb",
        "max_output_size_mb",
        "max_entry_uncompressed_mb",
        "verify_candidates",
    )
    return {key: limits.get(key) for key in selected}


def _path_fingerprint(path: str) -> dict[str, Any]:
    if not path:
        return {"path": ""}
    candidate = Path(path)
    try:
        stat = candidate.stat()
        return {
            "path": str(candidate),
            "size": int(stat.st_size),
            "mtime_ns": int(stat.st_mtime_ns),
        }
    except OSError:
        return {"path": str(candidate), "missing": True}


def _cache_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _cache_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_cache_jsonable(item) for item in value]
    if isinstance(value, set):
        return sorted(_cache_jsonable(item) for item in value)
    if isinstance(value, bytes):
        return {"bytes_sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def job_source_size(job: RepairJob) -> int | None:
    if job.archive_state is not None and job.archive_state.patches:
        try:
            from sunpack.support.archive_state_view import ArchiveStateByteView

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
