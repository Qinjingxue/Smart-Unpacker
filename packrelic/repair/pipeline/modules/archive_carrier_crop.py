from __future__ import annotations

from pathlib import Path

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.module import RepairModuleSpec, RepairRoute
from packrelic.repair.pipeline.modules._common import patch_plan_for_crop, source_input_for_job
from packrelic.repair.pipeline.modules._native_candidates import candidates_from_native_result
from packrelic.repair.pipeline.modules._native_validation import validate_with_native_probe
from packrelic.repair.pipeline.registry import register_repair_module
from packrelic.repair.result import RepairResult

from packrelic_native import archive_carrier_crop_recovery as _native_archive_carrier_crop_recovery


class ArchiveCarrierCropDeepRecovery:
    spec = RepairModuleSpec(
        name="archive_carrier_crop_deep_recovery",
        formats=("7z", "seven_zip", "rar", "archive"),
        categories=("boundary_repair", "content_recovery", "directory_rebuild"),
        stage="deep",
        safe=True,
        routes=(
            RepairRoute(
                formats=("7z", "seven_zip", "rar", "archive"),
                require_any_categories=("boundary_repair", "content_recovery", "directory_rebuild"),
                require_any_flags=("carrier_archive", "sfx", "embedded_archive", "carrier_prefix", "boundary_unreliable", "start_trusted_only"),
                require_any_fuzzy_hints=("carrier_prefix_likely", "entropy_boundary_shift"),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.84,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if diagnosis.format == "rar" and flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.65
        if flags & {"carrier_archive", "sfx", "embedded_archive", "boundary_unreliable", "start_trusted_only"}:
            return 0.9
        if "boundary_repair" in diagnosis.categories and diagnosis.format in {"7z", "seven_zip", "rar"}:
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
        )

    def _run_native(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> dict:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        return _native_archive_carrier_crop_recovery(
            source_input_for_job(job),
            diagnosis.format or job.format or "archive",
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            int(deep.get("max_candidates_per_module", 8) or 1),
        )


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
        return RepairResult(
            status=status,
            confidence=float(result.get("confidence") or 0.78),
            format=fmt,
            repaired_input={"kind": "file", "path": selected_path, "format_hint": fmt},
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=warnings,
            workspace_paths=list(result.get("workspace_paths") or []),
            partial=status == "partial",
            module_name=module_name,
            diagnosis={**diagnosis.as_dict(), "native_archive_deep_repair": dict(result), "native_probe": validation},
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
        confidence = float(item.get("confidence", result.get("confidence", 0.0)) or 0.0)
        item["patch_plan"] = patch_plan_for_crop(
            job,
            module_name,
            start,
            end,
            confidence=confidence,
            actions=actions,
        ).to_dict()
