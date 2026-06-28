from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.repair.job import RepairJob
from sunpack.repair.result import RepairResult
from sunpack.repair.runtime_cache import stable_cache_key
from sunpack.support.archive_state_view import ArchiveStateByteView, archive_state_from_source_input, archive_state_to_bytes

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
        base = dict(job.source_input or {})
        if not base and job.archive_state is not None:
            base = job.archive_state.source.to_archive_input_descriptor().to_source_input()
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
    if _should_expand_parts_to_concat(base):
        ranges: list[dict[str, Any]] = []
        seen: set[str] = set()
        source_parts_metadata = [_cache_jsonable(item) for item in base.get("parts") or [] if isinstance(item, dict)]
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
                "use_parts_only": bool(base.get("use_parts_only")),
                "split_sidecars_available": True,
                "logical_stream_built": True,
                "source_parts_metadata": source_parts_metadata,
            }
    if str(base.get("kind") or "") == "concat_ranges":
        base["logical_stream_built"] = True
        if len(list(base.get("ranges") or [])) > 1:
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
            split_sidecars_available = bool(base.get("split_sidecars_available")) or len(list(base.get("ranges") or [])) > 1
            base = {
                "kind": "file",
                "path": path,
                "format_hint": base.get("format_hint") or job.format,
                "use_parts_only": bool(base.get("use_parts_only")),
                "logical_stream_built": True,
                "split_sidecars_available": split_sidecars_available,
                "source_parts_metadata": base.get("source_parts_metadata"),
            }
    if (
        str(base.get("kind") or "file") == "file"
        and bool(base.get("logical_stream_built"))
        and isinstance(base.get("parts"), list)
    ):
        base["source_parts_metadata"] = [_cache_jsonable(item) for item in base.get("parts") or [] if isinstance(item, dict)]
        base.pop("parts", None)
    if job.password:
        base["password"] = job.password
    return base


def _should_expand_parts_to_concat(source_input: dict[str, Any]) -> bool:
    if str(source_input.get("kind") or "") == "concat_ranges":
        return False
    if not isinstance(source_input.get("parts"), list) or not source_input.get("parts"):
        return False
    # Once a split/logical stream has been materialized as a repaired file, the
    # original parts are only metadata. Re-expanding them would discard the
    # previous repair and send the loop back to the unmodified split source.
    if str(source_input.get("kind") or "file") == "file" and source_input.get("path") and bool(source_input.get("logical_stream_built")):
        return False
    return True


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
    if job.archive_state is not None and job.archive_state.patches:
        source = job.archive_state.source.to_archive_input_descriptor().to_source_input()
        fingerprint = {
            "kind": "archive_state",
            "source": source_fingerprint(source),
            "patch_digest": job.archive_state.effective_patch_digest(),
            "patch_depth": job.archive_state.patch_depth(),
            "format_hint": job.archive_state.format_hint or job.archive_state.source.format_hint or job.format,
        }
    else:
        fingerprint = source_fingerprint(source_input_for_job(job))
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


def _hash_view_range(view: ArchiveStateByteView, offset: int, size: int, *, chunk_size: int = 1024 * 1024) -> str:
    offset = max(0, int(offset))
    remaining = max(0, int(size))
    digest = hashlib.sha256()
    cursor = offset
    while remaining > 0:
        take = min(chunk_size, remaining)
        digest.update(view.read_at(cursor, take))
        cursor += take
        remaining -= take
    return digest.hexdigest()


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
    return source_input_size(source_input_for_job(job))


def base_archive_state_for_job(job: RepairJob) -> ArchiveState:
    if job.archive_state is not None and job.archive_state.patches:
        return job.archive_state
    source_input = source_input_for_job(job)
    if job.archive_state is not None and not _is_logical_source_input(source_input):
        return job.archive_state
    return archive_state_from_source_input(
        source_input,
        format_hint=job.format,
        logical_name=str(job.archive_key or ""),
    )


def _is_logical_source_input(source_input: dict[str, Any]) -> bool:
    kind = str(source_input.get("kind") or "")
    if kind == "concat_ranges":
        return True
    if bool(source_input.get("logical_stream_built")) or bool(source_input.get("split_sidecars_available")):
        return True
    if isinstance(source_input.get("parts"), list) and source_input.get("parts"):
        return True
    if isinstance(source_input.get("ranges"), list) and source_input.get("ranges"):
        return True
    return False


def patch_plan_for_byte_patches(
    job: RepairJob,
    module_name: str,
    patches: list[dict[str, Any]],
    *,
    confidence: float,
    actions: list[str],
) -> PatchPlan:
    base_state = base_archive_state_for_job(job)
    view = ArchiveStateByteView(base_state)
    operations = [
        PatchOperation.replace_bytes(
            offset=int(patch["offset"]),
            data=bytes(patch["data"]),
            expected=view.read_at(int(patch["offset"]), len(bytes(patch["data"]))),
            details={"module": module_name},
        )
        for patch in patches
    ]
    return PatchPlan(
        module=module_name,
        format=job.format,
        action_type="apply_patch",
        operations=operations,
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base_state.effective_patch_digest()},
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
        module=module_name,
        format=job.format,
        action_type="apply_patch",
        operations=[
            PatchOperation(
                op="insert",
                offset=int(offset),
                size=len(data),
                data_b64=base64.b64encode(bytes(data)).decode("ascii"),
                expected_b64="",
                details={"module": module_name},
            )
        ],
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base_archive_state_for_job(job).effective_patch_digest()},
        confidence=float(confidence),
    )


def patch_plan_for_truncate(job: RepairJob, module_name: str, size: int, *, confidence: float, actions: list[str]) -> PatchPlan:
    base = base_archive_state_for_job(job)
    view = ArchiveStateByteView(base)
    offset = max(0, min(int(size), view.size))
    return PatchPlan(
        module=module_name,
        format=job.format,
        action_type="apply_patch",
        operations=[PatchOperation(op="truncate", offset=int(size), size=0, expected_sha256=_hash_view_range(view, offset, view.size - offset), details={"module": module_name})],
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base.effective_patch_digest()},
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
    base = base_archive_state_for_job(job)
    view = ArchiveStateByteView(base)
    offset = max(0, min(int(size), view.size))
    return PatchPlan(
        module=module_name,
        format=job.format,
        action_type="apply_patch",
        operations=[
            PatchOperation(op="truncate", offset=int(size), size=0, expected_sha256=_hash_view_range(view, offset, view.size - offset), details={"module": module_name}),
            PatchOperation.append_bytes(bytes(data), details={"module": module_name}),
        ],
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base.effective_patch_digest()},
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
    base = base_archive_state_for_job(job)
    view = ArchiveStateByteView(base)
    end = min(end, view.size)
    operations: list[PatchOperation] = []
    if start:
        operations.append(PatchOperation.delete_range(offset=0, size=start, expected=view.read_at(0, min(start, view.size)), details={"module": module_name}))
    operations.append(PatchOperation(op="truncate", offset=end - start, size=0, expected_sha256=_hash_view_range(view, end, view.size - end), details={"module": module_name}))
    return PatchPlan(
        module=module_name,
        format=job.format,
        action_type="apply_patch",
        operations=operations,
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base.effective_patch_digest(), "crop_start": start, "crop_end": end},
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
    base = base_archive_state_for_job(job)
    view = ArchiveStateByteView(base)
    end = min(end, view.size)
    operations: list[PatchOperation] = []
    if start:
        operations.append(PatchOperation.delete_range(offset=0, size=start, expected=view.read_at(0, min(start, view.size)), details={"module": module_name}))
    operations.extend([
        PatchOperation(op="truncate", offset=end - start, size=0, expected_sha256=_hash_view_range(view, end, view.size - end), details={"module": module_name}),
        PatchOperation.append_bytes(bytes(data), details={"module": module_name}),
    ])
    return PatchPlan(
        module=module_name,
        format=job.format,
        action_type="apply_patch",
        operations=operations,
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base.effective_patch_digest(), "crop_start": start, "crop_end": end},
        confidence=float(confidence),
    )


def patch_plan_replace_logical_archive(
    job: RepairJob,
    module_name: str,
    new_bytes: bytes,
    *,
    confidence: float,
    actions: list[str],
) -> PatchPlan:
    base = base_archive_state_for_job(job)
    base_bytes = archive_state_to_bytes(base)
    return PatchPlan(
        module=module_name,
        format=job.format,
        action_type="apply_patch",
        operations=[
            PatchOperation(
                op="truncate",
                offset=0,
                size=0,
                expected_sha256=hashlib.sha256(base_bytes).hexdigest(),
                details={"module": module_name, "adapter": "replace_logical_archive"},
            ),
            PatchOperation.append_bytes(bytes(new_bytes), details={"module": module_name, "adapter": "replace_logical_archive"}),
        ],
        provenance={"module": module_name, "actions": list(actions), "base_patch_digest": base.effective_patch_digest(), "adapter": "replace_logical_archive"},
        confidence=float(confidence),
    )


def compact_replace_logical_patch_plan(job: RepairJob, patch_plan: PatchPlan, *, min_saved_bytes: int = 4096) -> PatchPlan:
    operations = list(patch_plan.operations)
    if len(operations) != 2:
        return patch_plan
    first, second = operations
    if first.op != "truncate" or int(first.offset or 0) != 0 or second.op != "append" or not second.data_b64:
        return patch_plan
    try:
        replacement = base64.b64decode(second.data_b64.encode("ascii"), validate=True)
    except Exception:
        return patch_plan
    base = base_archive_state_for_job(job)
    source = archive_state_to_bytes(base)
    compact_ops = _diff_patch_operations(
        source,
        replacement,
        module=patch_plan.module,
        native_target=str(first.details.get("native_target") or second.details.get("native_target") or ""),
    )
    if not compact_ops:
        return patch_plan
    old_bytes = sum(_operation_data_len(op) + len(op.expected_b64) for op in operations)
    new_bytes = sum(_operation_data_len(op) + len(op.expected_b64) for op in compact_ops)
    if old_bytes - new_bytes < int(min_saved_bytes):
        return patch_plan
    provenance = dict(patch_plan.provenance)
    provenance["compact_diff_adapter"] = {
        "source_size": len(source),
        "replacement_size": len(replacement),
        "original_operations": len(operations),
        "compact_operations": len(compact_ops),
    }
    return PatchPlan(
        schema_version=patch_plan.schema_version,
        module=patch_plan.module,
        format=patch_plan.format,
        action_type=patch_plan.action_type,
        operations=compact_ops,
        provenance=provenance,
        confidence=patch_plan.confidence,
    )


def _diff_patch_operations(source: bytes, replacement: bytes, *, module: str, native_target: str = "") -> list[PatchOperation]:
    if source == replacement:
        return []
    prefix = 0
    limit = min(len(source), len(replacement))
    while prefix < limit and source[prefix] == replacement[prefix]:
        prefix += 1
    suffix = 0
    max_suffix = min(len(source) - prefix, len(replacement) - prefix)
    while suffix < max_suffix and source[len(source) - 1 - suffix] == replacement[len(replacement) - 1 - suffix]:
        suffix += 1
    source_mid = source[prefix:len(source) - suffix if suffix else len(source)]
    replacement_mid = replacement[prefix:len(replacement) - suffix if suffix else len(replacement)]
    details = {"module": module, "adapter": "compact_binary_diff"}
    if native_target:
        details["native_target"] = native_target
    if not source_mid:
        return [PatchOperation(op="insert", offset=prefix, size=len(replacement_mid), data_b64=base64.b64encode(replacement_mid).decode("ascii"), expected_b64="", details=details)]
    if not replacement_mid:
        return [PatchOperation.delete_range(offset=prefix, size=len(source_mid), expected=source_mid if len(source_mid) <= 4096 else None, expected_sha256=hashlib.sha256(source_mid).hexdigest() if len(source_mid) > 4096 else "", details=details)]
    if len(source_mid) == len(replacement_mid):
        return [PatchOperation.replace_bytes(offset=prefix, data=replacement_mid, expected=source_mid if len(source_mid) <= 4096 else None, expected_sha256=hashlib.sha256(source_mid).hexdigest() if len(source_mid) > 4096 else "", details=details)]
    return [
        PatchOperation.delete_range(offset=prefix, size=len(source_mid), expected=source_mid if len(source_mid) <= 4096 else None, expected_sha256=hashlib.sha256(source_mid).hexdigest() if len(source_mid) > 4096 else "", details=details),
        PatchOperation(op="insert", offset=prefix, size=len(replacement_mid), data_b64=base64.b64encode(replacement_mid).decode("ascii"), expected_b64="", details=details),
    ]


def _operation_data_len(operation: PatchOperation) -> int:
    if not operation.data_b64:
        return 0
    try:
        return len(base64.b64decode(operation.data_b64.encode("ascii"), validate=True))
    except Exception:
        return len(operation.data_b64)


def patched_state_for_job(job: RepairJob, patch_plan: PatchPlan) -> ArchiveState:
    base = base_archive_state_for_job(job)
    state = base.push_patch(patch_plan)
    if state.format_hint or not job.format:
        return state
    return ArchiveState(
        source=state.source,
        patches=list(state.patches),
        patch_digest="",
        logical_name=state.logical_name,
        format_hint=job.format,
        analysis=dict(state.analysis),
        verification=dict(state.verification),
        knowledge=dict(state.knowledge),
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


def should_materialize_candidate(config: dict[str, Any], fmt: str = "") -> bool:
    if str(fmt or "").lower().lstrip(".") in {"zip", "7z", "seven_zip", "sevenzip"}:
        return bool(config.get("materialize_patch_candidate", False))
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
    patch_plan = compact_replace_logical_patch_plan(job, patch_plan)
    repaired_state = patched_state_for_job(job, patch_plan)
    path = ""
    if should_materialize_candidate(config, fmt):
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


def crop_source_input_ranges(source_input: dict[str, Any], cropped_start: int, cropped_end: int | None = None) -> dict[str, Any] | None:
    ranges = _logical_ranges_for_crop(source_input)
    if not ranges:
        return None
    start = max(0, int(cropped_start or 0))
    end = None if cropped_end is None or int(cropped_end) <= 0 else max(start, int(cropped_end))
    output_ranges: list[dict[str, Any]] = []
    cursor = 0
    for item in ranges:
        size = _range_size(item)
        if size is None:
            return None
        next_cursor = cursor + size
        if next_cursor <= start:
            cursor = next_cursor
            continue
        if end is not None and cursor >= end:
            break
        item_start = int(item.get("start") or 0)
        local_start = item_start + max(0, start - cursor)
        if end is None:
            local_end = item.get("end")
        else:
            take = max(0, min(next_cursor, end) - max(cursor, start))
            local_end = local_start + take
        if local_end is None or int(local_end) > local_start:
            output_ranges.append({**item, "start": local_start, "end": local_end})
        cursor = next_cursor
    if not output_ranges:
        return None
    result = {
        "kind": "concat_ranges",
        "ranges": output_ranges,
        "format_hint": source_input.get("format_hint") or source_input.get("format"),
        "parts": source_input.get("parts"),
        "use_parts_only": True,
        "logical_stream_built": True,
        "split_sidecars_available": bool(source_input.get("split_sidecars_available")) or bool(source_input.get("parts")) or len(output_ranges) > 1,
    }
    if source_input.get("password"):
        result["password"] = source_input.get("password")
    return {key: value for key, value in result.items() if value not in (None, "", [], {})}


def _logical_ranges_for_crop(source_input: dict[str, Any]) -> list[dict[str, Any]]:
    kind = str(source_input.get("kind") or "file")
    if kind == "concat_ranges":
        return [dict(item) for item in source_input.get("ranges") or [] if isinstance(item, dict) and item.get("path")]
    if isinstance(source_input.get("parts"), list) and source_input.get("parts"):
        ranges = []
        seen: set[str] = set()
        for part in source_input.get("parts") or []:
            if not isinstance(part, dict):
                continue
            path = str(part.get("path") or "")
            if not path or path in seen:
                continue
            seen.add(path)
            ranges.append({"path": path, "start": int(part.get("start") or 0), "end": part.get("end")})
        if ranges:
            return ranges
    if kind == "file_range":
        return [{
            "path": source_input.get("path"),
            "start": int(source_input.get("start") or 0),
            "end": source_input.get("end"),
        }]
    if kind == "file" and source_input.get("path"):
        return [{"path": source_input.get("path"), "start": 0, "end": None}]
    return []


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
