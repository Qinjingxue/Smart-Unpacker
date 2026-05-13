from __future__ import annotations

import hashlib
from typing import Any

from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.modules._common import (
    cached_repair_operation,
    cache_relevant_module_limits,
    module_limits,
    source_input_for_job,
)

try:
    from sunpack_native import seven_zip_scan_source as _native_seven_zip_scan_source
except Exception:  # pragma: no cover - native extension may be unavailable during static tooling
    _native_seven_zip_scan_source = None


def cached_seven_zip_scan_artifact(job: RepairJob, config: dict[str, Any] | None = None) -> dict[str, Any]:
    if _native_seven_zip_scan_source is None:
        return {
            "status": "unavailable",
            "native_key": "native_7z_scan_source",
            "native_target": "seven_zip_scan_source",
            "seven_zip_scan_artifact_miss_reason": "native_api_unavailable",
        }
    limits = module_limits(config)
    params = {
        "limits": cache_relevant_module_limits(
            config,
            ("max_input_size_mb", "max_next_header_scan_bytes", "max_candidates_per_module"),
        ),
        "password_present": bool(getattr(job, "password", None)),
        "password_fingerprint": password_fingerprint(getattr(job, "password", None)),
    }

    def compute() -> dict[str, Any]:
        return dict(_native_seven_zip_scan_source(
            source_input_for_job(job),
            float(limits.get("max_input_size_mb", 512) or 0),
            int(limits.get("max_next_header_scan_bytes", 1024 * 1024) or 1024 * 1024),
            int(limits.get("max_candidates_per_module", 8) or 1),
        ))

    result = dict(cached_repair_operation(job, "seven_zip_scan_artifact", "seven_zip_scan_source", params, compute))
    _write_scan_summary_to_job_knowledge(job, result)
    return result


def password_fingerprint(password: Any) -> str:
    if password in (None, ""):
        return ""
    return hashlib.sha256(str(password).encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _write_scan_summary_to_job_knowledge(job: RepairJob, scan: dict[str, Any]) -> None:
    if not isinstance(getattr(job, "knowledge", None), dict):
        return
    structure = scan.get("structure") if isinstance(scan.get("structure"), dict) else {}
    route_flags = [str(item) for item in scan.get("route_evidence_flags") or [] if str(item)]
    tags = [str(item) for item in scan.get("container_tags") or [] if str(item)]
    password_present = bool(scan.get("password_present"))
    digest = _scan_summary_digest(structure, route_flags, tags, password_present)
    meta = job.knowledge.setdefault("_meta", {})
    if not isinstance(meta, dict):
        meta = {}
        job.knowledge["_meta"] = meta
    markers = meta.setdefault("repair_cache_markers", {})
    if not isinstance(markers, dict):
        markers = {}
        meta["repair_cache_markers"] = markers
    if markers.get("seven_zip_scan_summary_digest") == digest:
        return
    if structure:
        _set_path(job.knowledge, "format.7z.structure", _jsonable(structure))
    if password_present:
        _set_path(job.knowledge, "archive.password_present", True)
    if route_flags:
        _add_flags(job.knowledge, "format.7z.route_evidence", route_flags)
        _add_flags(job.knowledge, "repair.route_evidence", route_flags)
        _add_flags(job.knowledge, "repair.damage", route_flags)
        _set_path(job.knowledge, "format.7z.route_evidence_flags", route_flags)
    if tags:
        _set_path(job.knowledge, "format.7z.container_tags", tags)
    markers["seven_zip_scan_summary_digest"] = digest


def _scan_summary_digest(structure: dict[str, Any], route_flags: list[str], tags: list[str], password_present: bool) -> str:
    import json

    payload = {
        "structure": _jsonable(structure),
        "route_flags": list(route_flags),
        "tags": list(tags),
        "password_present": bool(password_present),
    }
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


def _set_path(payload: dict[str, Any], path: str, value: Any) -> None:
    current = payload
    parts = [part for part in str(path or "").split(".") if part]
    for part in parts[:-1]:
        item = current.setdefault(part, {})
        if not isinstance(item, dict):
            item = {}
            current[part] = item
        current = item
    if parts:
        current[parts[-1]] = value


def _get_path(payload: dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = payload
    for part in [part for part in str(path or "").split(".") if part]:
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _add_flags(payload: dict[str, Any], namespace: str, flags: list[str]) -> None:
    path = f"{namespace}.flags" if namespace else "flags"
    existing = [str(item) for item in _get_path(payload, path, []) or [] if str(item)]
    merged: list[str] = []
    seen: set[str] = set()
    for item in [*existing, *flags]:
        if item in seen:
            continue
        seen.add(item)
        merged.append(item)
    _set_path(payload, path, merged)


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "to_dict"):
        try:
            return _jsonable(value.to_dict())
        except Exception:
            return str(value)
    return str(value)
