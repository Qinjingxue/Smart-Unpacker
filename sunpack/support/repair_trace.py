from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


_LOCK = threading.Lock()


def enabled() -> bool:
    return bool(_trace_path())


def write_event(event: str, payload: dict[str, Any] | None = None) -> None:
    path = _trace_path()
    if not path:
        return
    record = {
        "schema_version": 1,
        "event": str(event or ""),
        "timestamp": time.time(),
        **dict(payload or {}),
    }
    try:
        trace_path = Path(path)
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(_jsonable(record), ensure_ascii=False, sort_keys=True)
        with _LOCK:
            with trace_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.write("\n")
    except Exception:
        if _strict():
            raise


def job_payload(job: Any) -> dict[str, Any]:
    return {
        "source_input": _jsonable(getattr(job, "source_input", {})),
        "format": getattr(job, "format", ""),
        "confidence": getattr(job, "confidence", 0.0),
        "analysis_evidence": _jsonable(getattr(job, "analysis_evidence", None)),
        "analysis_prepass": _jsonable(getattr(job, "analysis_prepass", {})),
        "fuzzy_profile": _jsonable(getattr(job, "fuzzy_profile", {})),
        "extraction_failure": _jsonable(getattr(job, "extraction_failure", None)),
        "extraction_diagnostics": _jsonable(getattr(job, "extraction_diagnostics", {})),
        "damage_flags": list(getattr(job, "damage_flags", []) or []),
        "password_present": getattr(job, "password", None) is not None,
        "archive_key": getattr(job, "archive_key", ""),
        "workspace": getattr(job, "workspace", ""),
        "attempts": getattr(job, "attempts", 0),
        "source_descriptor": _jsonable(getattr(job, "source_descriptor", None)),
        "archive_state": _jsonable(getattr(job, "archive_state", None)),
    }


def result_payload(result: Any) -> dict[str, Any]:
    return {
        "status": getattr(result, "status", ""),
        "ok": bool(getattr(result, "ok", False)),
        "format": getattr(result, "format", ""),
        "confidence": getattr(result, "confidence", 0.0),
        "module_name": getattr(result, "module_name", ""),
        "partial": bool(getattr(result, "partial", False)),
        "actions": list(getattr(result, "actions", []) or []),
        "damage_flags": list(getattr(result, "damage_flags", []) or []),
        "repaired_input": _jsonable(getattr(result, "repaired_input", {})),
        "diagnosis": _jsonable(getattr(result, "diagnosis", {})),
        "warnings": list(getattr(result, "warnings", []) or []),
        "message": getattr(result, "message", ""),
    }


def _trace_path() -> str:
    return str(os.environ.get("SUNPACK_REPAIR_TRACE_JSONL") or "").strip()


def _strict() -> bool:
    return str(os.environ.get("SUNPACK_REPAIR_TRACE_STRICT") or "").strip().lower() in {"1", "true", "yes", "on"}


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "to_dict") and callable(value.to_dict):
        try:
            return _jsonable(value.to_dict())
        except Exception:
            pass
    return str(value)
