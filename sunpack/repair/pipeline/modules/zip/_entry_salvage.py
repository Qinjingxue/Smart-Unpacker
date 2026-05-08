from __future__ import annotations

from typing import Any

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.modules._common import cached_repair_operation, cache_relevant_module_limits, source_input_for_job, module_limits
from sunpack.repair.result import RepairResult
from sunpack_native import zip_verified_entry_salvage as _native_zip_verified_entry_salvage


def verification_problem_names(job: RepairJob) -> list[str]:
    coverage = coverage_view_from_job(job)
    names = [*coverage.failed_names, *coverage.partial_names, *coverage.missing_names]
    hints = _repair_hints(job)
    for key in (
        "failed_names",
        "failed_files",
        "partial_names",
        "partial_files",
        "missing_names",
        "missing_files",
        "wrong_hash_names",
        "crc_mismatch_names",
    ):
        value = hints.get(key)
        if isinstance(value, list):
            names.extend(str(item) for item in value if item)
    return _dedupe_names(names)


def run_verified_entry_salvage(
    *,
    module_name: str,
    job: RepairJob,
    diagnosis: RepairDiagnosis,
    workspace: str,
    config: dict[str, Any],
    exclude_names: list[str] | None = None,
    confidence: float = 0.86,
    message: str = "ZIP verified entry salvage produced a candidate",
    repair_name: str | None = None,
    native_key: str = "native_zip_verified_entry_salvage",
    atomic_action_group: str | None = None,
) -> RepairResult:
    limits = module_limits(config)
    source_input = source_input_for_job(job)
    action = repair_name or module_name
    excluded = list(exclude_names or [])
    params = {
        "source_input": source_input,
        "workspace": workspace,
        "repair_name": action,
        "exclude_names": excluded,
        "limits": cache_relevant_module_limits(config),
    }
    result = dict(cached_repair_operation(
        job,
        "native_zip_verified_entry_salvage",
        action,
        params,
        lambda: dict(_native_zip_verified_entry_salvage(
            source_input,
            workspace,
            action,
            excluded,
            int(limits.get("max_entries", 20000) or 20000),
            float(limits.get("max_input_size_mb", 512) or 0),
            float(limits.get("max_output_size_mb", 2048) or 0),
            float(limits.get("max_entry_uncompressed_mb", 512) or 0),
            float(limits.get("max_seconds_per_module", 30.0) or 0),
        )),
    ))
    status = str(result.get("status") or "unrepairable")
    selected_path = str(result.get("selected_path") or result.get("path") or "")
    verified_entries = int(result.get("verified_entries") or 0)
    if status not in {"repaired", "partial"} or not selected_path or verified_entries <= 0:
        return RepairResult(
            status="unrepairable" if status == "skipped" else status,
            confidence=0.0,
            format="zip",
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            module_name=module_name,
            diagnosis={**diagnosis.as_dict(), "repair_name": repair_name or module_name, "native_key": native_key, "atomic_action_group": atomic_action_group or repair_name or module_name, native_key: result},
            message=str(result.get("message") or "ZIP verified entry salvage did not produce a candidate"),
        )
    coverage = coverage_view_from_job(job)
    return RepairResult(
        status="partial",
        confidence=min(0.995, max(0.1, confidence + coverage.score_hint(payload=0.05, mixed=0.04, partial=0.03))),
        format="zip",
        repaired_input={"kind": "file", "path": selected_path, "format_hint": "zip"},
        actions=list(result.get("actions") or []),
        damage_flags=list(job.damage_flags),
        warnings=list(result.get("warnings") or []),
        workspace_paths=list(result.get("workspace_paths") or [selected_path]),
        partial=True,
        module_name=module_name,
        diagnosis={
            **diagnosis.as_dict(),
            "repair_name": repair_name or module_name,
            "native_key": native_key,
            "atomic_action_group": atomic_action_group or repair_name or module_name,
            "archive_coverage": coverage.as_dict(),
            "excluded_names": list(exclude_names or []),
            native_key: result,
        },
        message=message,
    )


def _repair_hints(job: RepairJob) -> dict[str, Any]:
    for payload in (job.extraction_failure, job.extraction_diagnostics):
        if isinstance(payload, dict):
            hints = payload.get("repair_hints")
            if isinstance(hints, dict):
                return hints
            nested = payload.get("verification")
            if isinstance(nested, dict) and isinstance(nested.get("repair_hints"), dict):
                return nested["repair_hints"]
    return {}


def _dedupe_names(names: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for name in names:
        normalized = str(name).replace("\\", "/").strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        output.append(normalized)
    return output
