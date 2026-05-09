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
        diagnostics = dict(result.diagnostics or {})
        worker = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
        payload = {
            "result": _result_payload(result),
            "diagnostics": diagnostics,
            "failure": _failure_payload(result, worker),
            "progress_manifest": result.progress_manifest_payload or {},
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


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
