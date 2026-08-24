from __future__ import annotations

import bz2
import gzip
import io
import lzma
from pathlib import Path
from typing import Any
import zlib

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.support.resource_lifecycle import read_task_bytes, write_task_bytes
from sunpack.repair.pipeline.modules._common import (
    module_limits,
    patch_diagnosis,
    patch_plan_for_truncate,
    patched_state_for_job,
    should_materialize_candidate,
    source_input_for_job,
    virtual_patch_repaired_input,
)
from sunpack.repair.result import RepairResult
from sunpack_native import compression_stream_trailing_junk_trim as _native_stream_trim


def native_stream_trailing_trim_result(
    *,
    module_name: str,
    fmt: str,
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    workspace: str,
    config: dict,
) -> RepairResult:
    limits = module_limits(config)
    result = dict(_native_stream_trim(
        source_input_for_job(job),
        fmt,
        workspace,
        float(limits.get("max_input_size_mb", 512) or 0),
        int(limits.get("max_trailing_junk_probe_bytes", 1024 * 1024) or 1024 * 1024),
        float(limits.get("max_seconds_per_module", 30.0) or 0),
        int(limits.get("max_stream_trim_probe_attempts", 32) or 32),
        float(limits.get("max_stream_trim_decode_mb", 64) or 64),
    ))
    status = str(result.get("status") or "unrepairable")
    if status != "repaired":
        fallback = _python_trailing_trim_result(
            module_name=module_name,
            fmt=fmt,
            job=job,
            diagnosis=diagnosis,
            workspace=workspace,
            config=config,
            native_result=result,
        )
        if fallback is not None:
            return fallback
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


def _python_trailing_trim_result(
    *,
    module_name: str,
    fmt: str,
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    workspace: str,
    config: dict,
    native_result: dict[str, Any],
) -> RepairResult | None:
    flags = set(job.damage_flags)
    if not (flags & {"trailing_junk", "boundary_unreliable", "trailing_padding"}):
        return None
    source = source_input_for_job(job)
    path = source.get("path") if isinstance(source, dict) else None
    if not path:
        return None
    try:
        data = read_task_bytes(Path(path))
    except OSError:
        return None
    truncate_at = _compressed_stream_end_offset(fmt, data)
    if truncate_at is None or truncate_at <= 0 or truncate_at >= len(data):
        return None
    target = Path(workspace) / f"{module_name}_trimmed.{_stream_extension(fmt)}"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        write_task_bytes(target, data[:truncate_at])
    except OSError:
        return None
    actions = ["python_stream_trailing_junk_trim"]
    confidence = 0.86
    patch_plan = patch_plan_for_truncate(job, module_name, truncate_at, confidence=confidence, actions=actions)
    repaired_state = patched_state_for_job(job, patch_plan)
    if should_materialize_candidate(config):
        repaired_input = {"kind": "file", "path": str(target), "format_hint": fmt}
        workspace_paths = [str(target)]
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
        warnings=list(native_result.get("warnings") or []),
        workspace_paths=workspace_paths,
        module_name=module_name,
        diagnosis=patch_diagnosis(
            {**diagnosis.as_dict(), "native_compression_stream_trim": native_result, "python_stream_trim": {"truncate_at": truncate_at}},
            patch_plan,
            repaired_state,
        ),
        repaired_state=repaired_state,
        message="trimmed trailing bytes after the compressed stream end",
    )


def _compressed_stream_end_offset(fmt: str, data: bytes) -> int | None:
    normalized = str(fmt or "").lower()
    try:
        if normalized in {"gzip", "gz"}:
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            decompressor.decompress(data)
            if decompressor.eof and decompressor.unused_data:
                return len(data) - len(decompressor.unused_data)
            return None
        if normalized in {"bzip2", "bz2"}:
            decompressor = bz2.BZ2Decompressor()
            decompressor.decompress(data)
            if decompressor.eof and decompressor.unused_data:
                return len(data) - len(decompressor.unused_data)
            return None
        if normalized == "xz":
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            decompressor.decompress(data)
            if decompressor.eof and decompressor.unused_data:
                return len(data) - len(decompressor.unused_data)
            return None
        if normalized in {"zstd", "zst"}:
            return _zstd_stream_end_offset(data)
    except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError):
        return None
    return None


def _zstd_stream_end_offset(data: bytes) -> int | None:
    try:
        import zstandard as zstd
    except Exception:
        return None
    decompressor = zstd.ZstdDecompressor()
    for end in range(1, len(data)):
        try:
            decompressor.decompress(data[:end])
        except Exception:
            continue
        return end
    try:
        stream = io.BytesIO(data)
        with zstd.ZstdDecompressor().stream_reader(stream) as reader:
            while reader.read(1024 * 1024):
                pass
        position = stream.tell()
    except Exception:
        return None
    if 0 < position < len(data):
        return position
    return None


def _stream_extension(fmt: str) -> str:
    normalized = str(fmt or "").lower()
    if normalized in {"gzip", "gz"}:
        return "gz"
    if normalized in {"bzip2", "bz2"}:
        return "bz2"
    if normalized in {"zstd", "zst"}:
        return "zst"
    return normalized or "bin"
