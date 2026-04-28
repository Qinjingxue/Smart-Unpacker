from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CONTENT_FAILURE_KINDS = {
    "checksum_error",
    "corrupted_data",
    "data_error",
    "unexpected_end",
    "input_truncated",
    "stream_truncated",
}
CONTENT_FAILURE_STAGES = {
    "item_extract",
    "archive_extract",
    "archive_read",
}


def build_extraction_progress_manifest(
    *,
    archive: str,
    out_dir: str,
    diagnostics: dict[str, Any],
    round_index: int = 1,
) -> dict[str, Any]:
    result = _worker_result(diagnostics)
    output_trace = _output_trace(result)
    items = [_manifest_item(item, round_index=round_index) for item in output_trace.get("items") or [] if isinstance(item, dict)]
    items = _merge_untraced_files(items, out_dir, round_index=round_index)
    summary = _summary(items)
    return {
        "version": 1,
        "archive": archive,
        "out_dir": out_dir,
        "partial_outputs": bool(summary["partial"] or summary["complete"] or summary["failed"]),
        "failure_stage": str(result.get("failure_stage") or diagnostics.get("failure_stage") or ""),
        "failure_kind": str(result.get("failure_kind") or diagnostics.get("failure_kind") or ""),
        "worker_status": str(result.get("status") or ""),
        "native_status": str(result.get("native_status") or ""),
        "files_written": int(result.get("files_written", 0) or output_trace.get("files_written", 0) or summary["complete"] + summary["partial"]),
        "bytes_written": int(result.get("bytes_written", 0) or output_trace.get("total_bytes_written", 0) or _sum_bytes(items)),
        "summary": summary,
        "files": items,
    }


def write_extraction_progress_manifest(
    *,
    archive: str,
    out_dir: str,
    diagnostics: dict[str, Any],
    round_index: int = 1,
) -> str:
    manifest = build_extraction_progress_manifest(
        archive=archive,
        out_dir=out_dir,
        diagnostics=diagnostics,
        round_index=round_index,
    )
    target = Path(out_dir) / ".sunpack" / "extraction_manifest.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(target)


def has_recoverable_partial_outputs(diagnostics: dict[str, Any], out_dir: str) -> bool:
    result = _worker_result(diagnostics)
    failure_stage = str(result.get("failure_stage") or diagnostics.get("failure_stage") or "")
    failure_kind = str(result.get("failure_kind") or diagnostics.get("failure_kind") or "")
    if failure_kind not in CONTENT_FAILURE_KINDS and failure_stage not in CONTENT_FAILURE_STAGES:
        return False
    if failure_kind in {"output_filesystem", "process_start", "process_timeout", "process_stall", "process_exit", "process_signal"}:
        return False
    output_trace = _output_trace(result)
    if _trace_has_progress(output_trace):
        return True
    if int(result.get("files_written", 0) or 0) > 0 or int(result.get("bytes_written", 0) or 0) > 0:
        return True
    return any(_iter_files(Path(out_dir)))


def _worker_result(diagnostics: dict[str, Any]) -> dict[str, Any]:
    result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    return dict(result)


def _output_trace(result: dict[str, Any]) -> dict[str, Any]:
    native = result.get("diagnostics") if isinstance(result.get("diagnostics"), dict) else {}
    trace = native.get("output_trace") if isinstance(native.get("output_trace"), dict) else {}
    return dict(trace)


def _trace_has_progress(output_trace: dict[str, Any]) -> bool:
    for item in output_trace.get("items") or []:
        if not isinstance(item, dict):
            continue
        if int(item.get("bytes_written", 0) or 0) > 0:
            return True
        if item.get("path") and not item.get("failed"):
            return True
    return False


def _manifest_item(item: dict[str, Any], *, round_index: int) -> dict[str, Any]:
    failed = bool(item.get("failed"))
    bytes_written = int(item.get("bytes_written", 0) or 0)
    status = "complete"
    if failed:
        status = "partial" if bytes_written > 0 else "failed"
    return {
        "path": str(item.get("path") or item.get("output_path") or ""),
        "archive_path": str(item.get("archive_path") or item.get("name") or item.get("path") or ""),
        "status": str(item.get("status") or status),
        "source_round": round_index,
        "bytes_written": bytes_written,
        "expected_size": _optional_int(item.get("expected_size", item.get("size"))),
        "crc_ok": item.get("crc_ok"),
        "failure_stage": str(item.get("failure_stage") or ""),
        "failure_kind": str(item.get("failure_kind") or ""),
        "message": str(item.get("message") or item.get("error") or ""),
    }


def _merge_untraced_files(items: list[dict[str, Any]], out_dir: str, *, round_index: int) -> list[dict[str, Any]]:
    seen = {str(item.get("path") or "") for item in items if item.get("path")}
    for path in _iter_files(Path(out_dir)):
        text = str(path)
        if text in seen or ".sunpack" in path.parts:
            continue
        items.append({
            "path": text,
            "archive_path": _relative_path(path, Path(out_dir)),
            "status": "unverified",
            "source_round": round_index,
            "bytes_written": path.stat().st_size,
            "expected_size": None,
            "crc_ok": None,
            "failure_stage": "",
            "failure_kind": "",
            "message": "file was present after partial extraction but was not reported by worker output trace",
        })
    return items


def _iter_files(root: Path):
    if not root.exists():
        return
    for item in root.rglob("*"):
        if item.is_file():
            yield item


def _summary(items: list[dict[str, Any]]) -> dict[str, int]:
    statuses = {"complete": 0, "partial": 0, "failed": 0, "skipped": 0, "unverified": 0}
    for item in items:
        status = str(item.get("status") or "unverified")
        statuses[status if status in statuses else "unverified"] += 1
    statuses["total"] = len(items)
    return statuses


def _sum_bytes(items: list[dict[str, Any]]) -> int:
    return sum(int(item.get("bytes_written", 0) or 0) for item in items)


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name

