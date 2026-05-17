from __future__ import annotations

from pathlib import Path
from typing import Any

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import cached_repair_operation, cache_relevant_module_limits, crop_source_input_ranges, patch_plan_for_crop, source_input_for_job, module_limits
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.modules._native_validation import validate_with_native_probe
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult

from sunpack_native import archive_carrier_crop_recovery as _native_archive_carrier_crop_recovery


class ArchiveCarrierCropDeepRecovery:
    spec = RepairModuleSpec(
        name="archive_carrier_crop_deep_recovery",
        formats=("7z", "seven_zip", "rar", "zip", "archive", "exe"),
        categories=("boundary_repair", "content_recovery", "directory_rebuild"),
        stage="deep",
        safe=True,
        atomic=True,
        route_family="carrier_crop",
        routes=(
            RepairRoute(
                formats=("7z", "seven_zip", "rar", "zip", "archive", "exe"),
                require_any_categories=(),
                require_any_flags=("carrier_archive", "sfx", "embedded_archive", "carrier_prefix", "boundary_unreliable", "start_trusted_only"),
                require_any_fuzzy_hints=("carrier_prefix_likely", "entropy_boundary_shift"),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.84,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        fmt = str(diagnosis.format or job.format or "").lower()
        if fmt not in {"7z", "seven_zip", "rar", "zip", "archive", "exe"}:
            return 0.0
        if "after_archive_carrier_crop" in flags or "already_tried:archive_carrier_crop_deep_recovery" in flags:
            return 0.0
        if fmt == "rar" and flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.65
        if fmt == "zip" and flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.98
        if fmt == "zip":
            return 0.0
        if fmt == "exe" and flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.9
        if flags & {"carrier_archive", "sfx", "embedded_archive", "boundary_unreliable", "start_trusted_only"}:
            return 0.9
        if "boundary_repair" in diagnosis.categories and fmt in {"7z", "seven_zip", "rar"}:
            return 0.74
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        result = self._run_native(job, diagnosis, workspace, config)
        return _result_from_native(self.spec.name, result, job, diagnosis, config)

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, diagnosis, workspace, config)
        normalize_native_candidate_lengths(result)
        if bool(config.get("virtual_patch_candidate")):
            attach_native_crop_patch_plans(result, job, self.spec.name)
        return candidates_from_native_result(
            self.spec.name,
            result,
            job,
            diagnosis,
            native_key="native_archive_deep_repair",
            default_confidence=0.78,
            default_message="archive carrier crop produced a candidate",
            prefer_patch_plan=bool(config.get("virtual_patch_candidate")),
            force_archive_state=bool(config.get("virtual_patch_candidate")),
        )

    def _run_native(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> dict:
        limits = module_limits(config)
        source_input = _carrier_crop_source_input(job)
        fmt = diagnosis.format or job.format or "archive"
        params = {
            "source_input": source_input,
            "format": fmt,
            "workspace": workspace,
            "limits": cache_relevant_module_limits(config, ("max_input_size_mb", "max_candidates_per_module")),
        }
        return cached_repair_operation(
            job,
            "native_archive_carrier_crop_recovery",
            self.spec.name,
            params,
            lambda: dict(_native_archive_carrier_crop_recovery(
                source_input,
                fmt,
                workspace,
                float(limits.get("max_input_size_mb", 512) or 0),
                int(limits.get("max_candidates_per_module", 8) or 1),
            )),
        )


def _carrier_crop_source_input(job: RepairJob) -> dict[str, Any]:
    source_input = source_input_for_job(job)
    if str(source_input.get("kind") or "") != "concat_ranges":
        return source_input
    main_path = str(source_input.get("path") or job.source_input.get("path") or "")
    for part in source_input.get("parts") or job.source_input.get("parts") or []:
        if not isinstance(part, dict):
            continue
        role = str(part.get("role") or "").lower()
        path = str(part.get("path") or "")
        if path and role in {"main", "primary", "carrier"}:
            main_path = path
            break
    if not main_path:
        ranges = source_input.get("ranges") if isinstance(source_input.get("ranges"), list) else []
        if ranges and isinstance(ranges[0], dict):
            main_path = str(ranges[0].get("path") or "")
    if not main_path:
        return source_input
    output = {
        "kind": "file",
        "path": main_path,
        "format_hint": source_input.get("format_hint") or job.format,
        "parts": source_input.get("parts") or job.source_input.get("parts"),
        "split_sidecars_available": bool(source_input.get("parts") or job.source_input.get("parts")),
    }
    if source_input.get("password"):
        output["password"] = source_input.get("password")
    return output


def _result_from_native(module_name: str, result: dict, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> RepairResult:
    normalize_native_candidate_lengths(result)
    status = str(result.get("status") or "unrepairable")
    selected_path = str(result.get("selected_path") or "")
    fmt = str(result.get("format") or diagnosis.format or job.format or "archive")
    warnings = list(result.get("warnings") or [])
    validation: dict = {}
    if status in {"repaired", "partial"} and selected_path:
        ok, validation_warnings, validation = validate_with_native_probe(selected_path, fmt, config)
        warnings.extend(validation_warnings)
        if not ok:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format=fmt,
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=warnings,
                workspace_paths=list(result.get("workspace_paths") or []),
                module_name=module_name,
                diagnosis={**diagnosis.as_dict(), "native_archive_deep_repair": dict(result), "native_probe": validation},
                message="native probe rejected repaired candidate",
            )
        repaired_input = _split_aware_repaired_input_from_native(result, job, fmt)
        if repaired_input is None:
            repaired_input = {"kind": "file", "path": selected_path, "format_hint": fmt}
        diagnosis_payload = {**diagnosis.as_dict(), "native_archive_deep_repair": dict(result), "native_probe": validation}
        if str(repaired_input.get("kind") or "") == "concat_ranges":
            patch_facts = [str(value) for value in diagnosis_payload.get("patch_facts") or []]
            patch_facts.append("split_logical_stream_preserved_after_crop")
            diagnosis_payload["patch_facts"] = _dedupe(patch_facts)
        return RepairResult(
            status=status,
            confidence=float(result.get("confidence") or 0.78),
            format=fmt,
            repaired_input=repaired_input,
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=warnings,
            workspace_paths=list(result.get("workspace_paths") or []),
            partial=status == "partial",
            module_name=module_name,
            diagnosis=diagnosis_payload,
            message=str(result.get("message") or "archive carrier crop produced a candidate"),
        )
    return RepairResult(
        status="unrepairable" if status in {"skipped", "unsupported"} else status,
        confidence=float(result.get("confidence") or 0.0),
        format=fmt,
        actions=list(result.get("actions") or []),
        damage_flags=list(job.damage_flags),
        warnings=warnings,
        workspace_paths=list(result.get("workspace_paths") or []),
        module_name=module_name,
        diagnosis={**diagnosis.as_dict(), "native_archive_deep_repair": dict(result)},
        message=str(result.get("message") or "archive carrier crop did not produce a candidate"),
    )


register_repair_module(ArchiveCarrierCropDeepRecovery())


def _split_aware_repaired_input_from_native(result: dict, job: RepairJob, fmt: str) -> dict[str, Any] | None:
    source = dict(job.source_input or {})
    if str(source.get("kind") or "") != "concat_ranges" and not source.get("parts"):
        source = source_input_for_job(job)
    if str(source.get("kind") or "") != "concat_ranges" and not source.get("parts"):
        return None
    try:
        start = int(result.get("offset") or result.get("cropped_start") or 0)
    except (TypeError, ValueError):
        return None
    end = None
    for key in ("end_offset", "cropped_end"):
        try:
            value = result.get(key)
            if value is not None and int(value) > 0:
                end = int(value)
                break
        except (TypeError, ValueError):
            continue
    if _is_split_logical_source(source):
        actions = {str(item) for item in result.get("actions") or []}
        facts = {str(item) for item in result.get("patch_facts") or []}
        target = str(result.get("native_target") or "")
        is_prefix_crop = (
            "crop_archive_carrier_prefix" in actions
            or "crop_7z_carrier_prefix" in actions
            or "after_archive_carrier_crop" in facts
            or target in {"archive_carrier_crop", "carrier_prefix"}
        )
        if is_prefix_crop:
            end = None
    repaired = crop_source_input_ranges(source, start, end)
    if repaired is None:
        return None
    repaired["format_hint"] = fmt
    if job.password is not None:
        repaired["password"] = job.password
    return repaired


def _is_split_logical_source(source: dict[str, Any]) -> bool:
    if bool(source.get("split_sidecars_available")) or bool(source.get("logical_stream_built")):
        return True
    if isinstance(source.get("parts"), list) and len(source.get("parts") or []) > 1:
        return True
    if str(source.get("kind") or "") == "concat_ranges" and len(source.get("ranges") or []) > 1:
        return True
    return False


def normalize_native_candidate_lengths(result: dict) -> None:
    candidates = list(result.get("candidates") or [])
    selected_path = str(result.get("selected_path") or "")
    if selected_path:
        candidates.append({
            "path": selected_path,
            "output_bytes": result.get("output_bytes"),
        })
    for item in candidates:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "")
        try:
            output_bytes = int(item.get("output_bytes") or 0)
        except (TypeError, ValueError):
            continue
        if output_bytes <= 0 or not path:
            continue
        _truncate_if_longer(path, output_bytes)


def _truncate_if_longer(path: str, output_bytes: int) -> None:
    candidate = Path(path)
    try:
        if not candidate.is_file() or candidate.stat().st_size <= output_bytes:
            return
        with candidate.open("r+b") as handle:
            handle.truncate(output_bytes)
    except OSError:
        return


def attach_native_crop_patch_plans(result: dict, job: RepairJob, module_name: str) -> None:
    for item in result.get("candidates") or []:
        if not isinstance(item, dict) or isinstance(item.get("patch_plan"), dict):
            continue
        try:
            start = int(item.get("offset") or 0)
            end = int(item.get("end_offset") or item.get("output_bytes") or 0)
        except (TypeError, ValueError):
            continue
        if end <= start:
            continue
        actions = list(item.get("actions") or result.get("actions") or [])
        actions = _dedupe([*actions, "crop_archive_carrier_prefix"])
        confidence = float(item.get("confidence", result.get("confidence", 0.0)) or 0.0)
        item["patch_facts"] = _dedupe([
            *[str(value) for value in item.get("patch_facts") or []],
            "fixed_field=carrier_prefix_crop",
            "after_archive_carrier_crop",
            "cropped_format=zip" if str(job.format or "").lower() == "zip" else f"cropped_format={job.format or 'archive'}",
            f"cropped_start={start}",
            f"cropped_end={end}",
        ])
        item["patch_plan"] = patch_plan_for_crop(
            job,
            module_name,
            start,
            end,
            confidence=confidence,
            actions=actions,
        ).to_dict()


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "")
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output
