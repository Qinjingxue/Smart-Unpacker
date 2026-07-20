from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Any

from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path


@dataclass(frozen=True)
class SevenZipDryRunResult:
    ok: bool
    returncode: int
    result: dict[str, Any] = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    progress: list[dict[str, Any]] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    message: str = ""


@dataclass(frozen=True)
class SevenZipMetadataOpenResult:
    ok: bool
    is_archive: bool
    status: str
    archive_type: str = ""
    item_count: int = 0
    encrypted: bool = False
    timed_out: bool = False
    message: str = ""


def open_archive_metadata(
    archive_path: str,
    *,
    part_paths: list[str] | None = None,
    format_hint: str = "",
    timeout: float = 1.5,
) -> SevenZipMetadataOpenResult:
    worker_path = get_sevenzip_bridge_worker_path()
    payload = {
        "job_id": f"metadata-open-{uuid.uuid4().hex}",
        "worker_command": "metadata_probe",
        "seven_zip_dll_path": get_7z_dll_path(),
        "archive_path": str(archive_path),
        "part_paths": list(dict.fromkeys(part_paths or [archive_path])),
        "format_hint": str(format_hint or ""),
    }
    try:
        completed = subprocess.run(
            [worker_path],
            input=json.dumps(payload, ensure_ascii=False),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=max(0.1, float(timeout or 1.5)),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return SevenZipMetadataOpenResult(False, False, "timeout", timed_out=True, message="metadata open timed out")
    except OSError as exc:
        return SevenZipMetadataOpenResult(False, False, "unavailable", message=str(exc))
    events = _parse_worker_json_lines(completed.stdout)
    result = next((item for item in reversed(events) if item.get("type") == "result"), {})
    status = str(result.get("native_status") or result.get("status") or "error")
    is_archive = bool(result.get("is_archive"))
    return SevenZipMetadataOpenResult(
        ok=completed.returncode == 0 and status == "ok" and is_archive,
        is_archive=is_archive,
        status=status,
        archive_type=str(result.get("archive_type") or ""),
        item_count=int(result.get("item_count") or 0),
        encrypted=bool(result.get("encrypted")),
        message=str(result.get("message") or completed.stderr or "metadata open failed"),
    )


def dry_run_archive(
    archive_path: str,
    *,
    format_hint: str = "",
    password: str = "",
    timeout: float = 30.0,
) -> SevenZipDryRunResult:
    worker_path = get_sevenzip_bridge_worker_path()
    seven_zip_dll_path = get_7z_dll_path()
    job_id = f"repair-dry-run-{uuid.uuid4().hex}"
    payload = {
        "job_id": job_id,
        "seven_zip_dll_path": seven_zip_dll_path,
        "archive_path": str(archive_path),
        "output_dir": "",
        "password": str(password or ""),
        "format_hint": str(format_hint or ""),
        "dry_run": True,
    }
    try:
        completed = subprocess.run(
            [worker_path],
            input=json.dumps(payload, ensure_ascii=False),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=max(1.0, float(timeout or 30.0)),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _coerce_text(exc.stdout)
        stderr = _coerce_text(exc.stderr)
        return SevenZipDryRunResult(
            ok=False,
            returncode=-101,
            result={
                "type": "result",
                "job_id": job_id,
                "status": "failed",
                "failure_stage": "worker_timeout",
                "failure_kind": "process_timeout",
            },
            stdout=stdout,
            stderr=stderr,
            message="sevenzip_worker dry-run timed out",
        )
    except OSError as exc:
        return SevenZipDryRunResult(
            ok=False,
            returncode=-100,
            result={
                "type": "result",
                "job_id": job_id,
                "status": "failed",
                "failure_stage": "worker_start",
                "failure_kind": "process_start",
            },
            stderr=str(exc),
            message=f"sevenzip_worker dry-run failed to start: {exc}",
        )

    events = _parse_worker_json_lines(completed.stdout)
    result = next((item for item in reversed(events) if item.get("type") == "result"), {})
    progress = [item for item in events if item.get("type") == "progress"]
    if not result:
        result = {
            "type": "result",
            "job_id": job_id,
            "status": "failed",
            "failure_stage": "worker_protocol",
            "failure_kind": "process_io",
        }
    diagnostics = result.get("diagnostics") if isinstance(result.get("diagnostics"), dict) else {}
    ok = completed.returncode == 0 and result.get("status") == "ok"
    message = str(result.get("message") or completed.stderr or ("worker dry-run ok" if ok else "worker dry-run failed"))
    return SevenZipDryRunResult(
        ok=ok,
        returncode=int(completed.returncode),
        result=dict(result),
        diagnostics=dict(diagnostics),
        progress=progress,
        stdout=completed.stdout,
        stderr=completed.stderr,
        message=message,
    )


def _parse_worker_json_lines(stdout: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in str(stdout or "").splitlines():
        text = line.strip()
        if not text.startswith("{"):
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    return events


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
