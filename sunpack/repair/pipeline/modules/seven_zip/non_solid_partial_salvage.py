from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack_native import seven_zip_non_solid_partial_salvage as _native_7z_non_solid_salvage


class SevenZipNonSolidPartialSalvage:
    spec = RepairModuleSpec(
        name="seven_zip_non_solid_partial_salvage",
        formats=("7z", "seven_zip"),
        categories=("content_recovery", "directory_rebuild"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("7z", "seven_zip"),
                require_any_categories=("content_recovery", "directory_rebuild"),
                require_any_flags=(
                    "non_solid",
                    "folder_bad",
                    "packed_stream_bad",
                    "damaged",
                    "crc_error",
                    "checksum_error",
                    "data_error",
                ),
                require_any_failure_kinds=("corrupted_data", "data_error", "checksum_error"),
                reject_any_flags=("wrong_password", "encrypted", "solid_block_damaged"),
                base_score=0.9,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"wrong_password", "encrypted", "solid_block_damaged"}:
            return 0.0
        if flags & {"non_solid", "folder_bad", "packed_stream_bad", "damaged", "crc_error", "checksum_error", "data_error"}:
            return 0.93 if "non_solid" in flags else 0.86
        if diagnosis.format in {"7z", "seven_zip"} and "content_recovery" in diagnosis.categories:
            return 0.78
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        candidates = self._candidates_from_native(result, job, diagnosis)
        if candidates:
            return candidates[0].to_result(selection={"selected_module": self.spec.name})
        from sunpack.repair.result import RepairResult

        return RepairResult(
            status="unrepairable",
            confidence=float(result.get("confidence") or 0.0),
            format="zip",
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            partial=True,
            module_name=self.spec.name,
            diagnosis={**diagnosis.as_dict(), "native_7z_non_solid_salvage": result},
            message=str(result.get("message") or "7z non-solid partial salvage did not produce a candidate"),
        )

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        return self._candidates_from_native(self._run_native(job, workspace, config), job, diagnosis)

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        return dict(_native_7z_non_solid_salvage(
            source_input_for_job(job),
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            int(deep.get("max_entries", 20000) or 20000),
        ))

    def _candidates_from_native(self, result: dict, job: RepairJob, diagnosis: RepairDiagnosis):
        return candidates_from_native_result(
            self.spec.name,
            result,
            job,
            diagnosis,
            native_key="native_7z_non_solid_salvage",
            format_hint="zip",
            partial_default=True,
            default_confidence=0.68,
            default_message="7z non-solid partial salvage produced a ZIP candidate",
        )


register_repair_module(SevenZipNonSolidPartialSalvage())
