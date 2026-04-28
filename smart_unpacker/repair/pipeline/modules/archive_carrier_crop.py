from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules._native_validation import validate_with_native_probe
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from smart_unpacker_native import archive_carrier_crop_recovery as _native_archive_carrier_crop_recovery


class ArchiveCarrierCropDeepRecovery:
    spec = RepairModuleSpec(
        name="archive_carrier_crop_deep_recovery",
        formats=("7z", "seven_zip", "rar", "archive"),
        categories=("boundary_repair", "content_recovery", "directory_rebuild"),
        stage="deep",
        safe=True,
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "boundary_unreliable", "start_trusted_only"}:
            return 0.9
        if "boundary_repair" in diagnosis.categories and diagnosis.format in {"7z", "seven_zip", "rar"}:
            return 0.74
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = _native_archive_carrier_crop_recovery(
            job.source_input,
            diagnosis.format or job.format or "archive",
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            int(deep.get("max_candidates_per_module", 8) or 1),
        )
        return _result_from_native(self.spec.name, result, job, diagnosis, config)


def _result_from_native(module_name: str, result: dict, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> RepairResult:
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
