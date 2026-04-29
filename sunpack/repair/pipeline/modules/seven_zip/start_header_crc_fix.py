from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import seven_zip_crc_field_repair as _native_seven_zip_crc_field_repair


class SevenZipStartHeaderCrcFix:
    spec = RepairModuleSpec(
        name="seven_zip_start_header_crc_fix",
        formats=("7z", "seven_zip"),
        categories=("directory_rebuild", "safe_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("7z", "seven_zip"),
                require_any_categories=("directory_rebuild", "safe_repair"),
                require_any_flags=("start_header_crc_bad", "start_header_corrupt"),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.76,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"start_header_crc_bad", "start_header_corrupt"}:
            return 0.86
        if diagnosis.format in {"7z", "seven_zip"} and "safe_repair" in diagnosis.categories:
            return 0.35
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(
            _native_seven_zip_crc_field_repair(
                source_input_for_job(job),
                workspace,
                float(deep.get("max_input_size_mb", 512) or 0),
                int(deep.get("max_candidates_per_module", 8) or 1),
            )
        )
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")
        if status == "repaired" and selected_path:
            return RepairResult(
                status="repaired",
                confidence=float(result.get("confidence") or 0.86),
                format="7z",
                repaired_input={"kind": "file", "path": selected_path, "format_hint": "7z"},
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or [selected_path]),
                module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "native_seven_zip_crc_field_repair": result},
                message=str(result.get("message") or "native 7z start header CRC repair produced a candidate"),
            )
        return RepairResult(
            status="unrepairable" if status in {"skipped", "unsupported"} else status,
            confidence=float(result.get("confidence") or 0.0),
            format="7z",
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            module_name=self.spec.name,
            diagnosis={**diagnosis.as_dict(), "native_seven_zip_crc_field_repair": result},
            message=str(result.get("message") or "native 7z start header CRC repair did not produce a candidate"),
        )


register_repair_module(SevenZipStartHeaderCrcFix())
