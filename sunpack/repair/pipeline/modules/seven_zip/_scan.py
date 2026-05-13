from __future__ import annotations

import hashlib
from typing import Any

from sunpack.contracts.archive_knowledge import ArchiveKnowledge
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
    knowledge = ArchiveKnowledge.from_any(job.knowledge)
    structure = scan.get("structure") if isinstance(scan.get("structure"), dict) else {}
    route_flags = [str(item) for item in scan.get("route_evidence_flags") or [] if str(item)]
    tags = [str(item) for item in scan.get("container_tags") or [] if str(item)]
    password_present = bool(scan.get("password_present"))
    if structure:
        knowledge.set("format.7z.structure", structure, source_layer="repair", source_module="seven_zip_scan")
    if password_present:
        knowledge.set("archive.password_present", True, source_layer="repair", source_module="seven_zip_scan")
    if route_flags:
        knowledge.add_flags("format.7z.route_evidence", route_flags, source_layer="repair", source_module="seven_zip_scan")
        knowledge.add_flags("repair.route_evidence", route_flags, source_layer="repair", source_module="seven_zip_scan")
        knowledge.add_flags("repair.damage", route_flags, source_layer="repair", source_module="seven_zip_scan")
        knowledge.set("format.7z.route_evidence_flags", route_flags, source_layer="repair", source_module="seven_zip_scan")
    if tags:
        knowledge.set("format.7z.container_tags", tags, source_layer="repair", source_module="seven_zip_scan")
    job.knowledge.clear()
    job.knowledge.update(knowledge.to_dict())
