from __future__ import annotations

from contextlib import nullcontext
from typing import Any, Callable

from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.result import ExtractionResult
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_payload


def write_extraction_result(task: ArchiveTask, result: ExtractionResult, *, phase_timer: Callable[..., Any] | None = None, phase_prefix: str = "write_extraction") -> None:
    with _phase(phase_timer, f"{phase_prefix}_ensure_knowledge"):
        knowledge = ensure_knowledge(task)
    with _phase(phase_timer, f"{phase_prefix}_build_payload"):
        diagnostics = _compact_diagnostics(dict(result.diagnostics or {}))
        worker = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
        payload = {
            "result": _result_payload(result),
            "diagnostics": diagnostics,
            "failure": _failure_payload(result, worker),
            "progress_manifest": _compact_progress_manifest(result.progress_manifest_payload or {}),
        }
    with _phase(phase_timer, f"{phase_prefix}_write_payload"):
        write_payload(
            knowledge,
            "extraction",
            payload,
            source_layer="extraction",
            source_module="scheduler",
        )
    with _phase(phase_timer, f"{phase_prefix}_commit"):
        commit_task_knowledge(task, knowledge, phase_timer=phase_timer, phase_prefix=f"{phase_prefix}_commit")


def _result_payload(result: ExtractionResult) -> dict[str, Any]:
    return {
        "success": bool(result.success),
        "archive": result.archive,
        "out_dir": result.out_dir,
        "all_parts": list(result.all_parts or []),
        "error": result.error,
        "password_used": result.password_used,
        "selected_codepage": result.selected_codepage,
        "partial_outputs": bool(result.partial_outputs),
        "progress_manifest": result.progress_manifest,
    }


def _failure_payload(result: ExtractionResult, worker: dict[str, Any]) -> dict[str, Any]:
    if result.success:
        return {}
    return {
        "status": str(worker.get("status") or "failed"),
        "failure_stage": str(worker.get("failure_stage") or ""),
        "failure_kind": str(worker.get("failure_kind") or ""),
        "native_status": str(worker.get("native_status") or ""),
        "error": result.error,
        "partial_outputs": bool(result.partial_outputs),
        "failed_item": worker.get("failed_item"),
    }


def _compact_diagnostics(diagnostics: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in (
        "status",
        "failure_stage",
        "failure_kind",
        "native_status",
        "returncode",
        "files_written",
        "bytes_written",
        "error",
        "message",
        "partial_outputs",
    ):
        if key in diagnostics:
            output[key] = diagnostics.get(key)
    result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    if result:
        output["result"] = _compact_worker_result(result)
    for key in ("output_trace", "segments", "embedded_segments"):
        value = diagnostics.get(key)
        if isinstance(value, dict):
            output[key] = _compact_mapping(value, max_items=30)
        elif isinstance(value, list):
            output[key] = [_compact_mapping(item, max_items=20) if isinstance(item, dict) else item for item in value[:20]]
            if len(value) > 20:
                output[key].append({"truncated_count": len(value) - 20})
    return output


def _compact_worker_result(result: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in (
        "status",
        "failure_stage",
        "failure_kind",
        "native_status",
        "returncode",
        "files_written",
        "bytes_written",
        "failed_item",
        "message",
        "damaged",
        "checksum_error",
        "crc_error",
        "wrong_password",
        "missing_volume",
        "unsupported_method",
        "output_filesystem",
    ):
        if key in result:
            output[key] = result.get(key)
    native = result.get("diagnostics") if isinstance(result.get("diagnostics"), dict) else {}
    if native:
        output["diagnostics"] = _compact_native_diagnostics(native)
    return output


def _compact_native_diagnostics(native: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key in (
        "failure_stage",
        "failure_kind",
        "native_status",
        "operation_result_name",
        "process_failure",
        "damaged",
        "checksum_error",
        "crc_error",
        "wrong_password",
        "missing_volume",
        "unsupported_method",
        "output_filesystem",
        "files_written",
        "bytes_written",
        "stderr_tail",
        "stdout_tail",
    ):
        if key in native:
            value = native.get(key)
            if isinstance(value, str) and key in {"stderr_tail", "stdout_tail"}:
                value = value[-4000:]
            output[key] = value
    if isinstance(native.get("last_progress_event"), dict):
        output["last_progress_event"] = _compact_mapping(native["last_progress_event"], max_items=20)
    progress_events = native.get("progress_events") if isinstance(native.get("progress_events"), list) else []
    if progress_events:
        output["progress_event_count"] = len(progress_events)
        if isinstance(progress_events[-1], dict):
            output["last_progress_event"] = _compact_mapping(progress_events[-1], max_items=20)
    return output


def _compact_progress_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        return {}
    output: dict[str, Any] = {}
    for key in ("summary", "files_written", "bytes_written", "status", "failure_stage", "failure_kind"):
        if key in manifest:
            value = manifest.get(key)
            output[key] = _compact_mapping(value, max_items=20) if isinstance(value, dict) else value
    for key in ("items", "entries", "outputs"):
        values = manifest.get(key)
        if isinstance(values, list):
            output[key] = [_compact_mapping(item, max_items=20) if isinstance(item, dict) else item for item in values[:50]]
            if len(values) > 50:
                output[key].append({"truncated_count": len(values) - 50})
    return output


def _compact_mapping(value: dict[str, Any], *, max_items: int) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for index, (key, item) in enumerate(value.items()):
        if index >= max_items:
            output["truncated_count"] = len(value) - max_items
            break
        text_key = str(key)
        if text_key in {"archive_state", "request_payload", "job", "candidate_features", "workspace_paths"}:
            output[text_key] = _large_placeholder(item)
        elif isinstance(item, dict):
            output[text_key] = _compact_mapping(item, max_items=max_items)
        elif isinstance(item, list):
            output[text_key] = [_compact_mapping(child, max_items=10) if isinstance(child, dict) else child for child in item[:20]]
            if len(item) > 20:
                output[text_key].append({"truncated_count": len(item) - 20})
        elif isinstance(item, str) and len(item) > 4000:
            output[text_key] = item[:4000]
        else:
            output[text_key] = item
    return output


def _large_placeholder(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {"omitted": True, "kind": "dict", "keys": sorted(str(key) for key in value.keys())[:20], "key_count": len(value)}
    if isinstance(value, list):
        return {"omitted": True, "kind": "list", "count": len(value)}
    return {"omitted": True, "kind": type(value).__name__}


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
