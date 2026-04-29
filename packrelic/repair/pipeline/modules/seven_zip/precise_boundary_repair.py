from __future__ import annotations

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.module import RepairModuleSpec, RepairRoute
from packrelic.repair.pipeline.modules._common import source_input_for_job
from packrelic.repair.pipeline.modules.archive_carrier_crop import _result_from_native, attach_native_crop_patch_plans
from packrelic.repair.pipeline.modules._native_candidates import candidates_from_native_result
from packrelic.repair.pipeline.registry import register_repair_module

from packrelic_native import seven_zip_precise_boundary_repair as _native_seven_zip_precise_boundary_repair


class SevenZipPreciseBoundaryRepair:
    spec = RepairModuleSpec(
        name="seven_zip_precise_boundary_repair",
        formats=("7z", "seven_zip"),
        categories=("boundary_repair",),
        stage="deep",
        safe=True,
        routes=(
            RepairRoute(
                formats=("7z", "seven_zip"),
                require_any_categories=("boundary_repair",),
                require_any_flags=("trailing_junk", "boundary_unreliable", "carrier_archive", "sfx", "embedded_archive", "carrier_prefix"),
                require_any_fuzzy_hints=("carrier_prefix_likely", "trailing_text_junk_likely", "trailing_padding_likely"),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.9,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.98
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.62
        if "boundary_repair" in diagnosis.categories:
            return 0.55
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        return _result_from_native(self.spec.name, result, job, diagnosis, config)

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        if bool(config.get("virtual_patch_candidate")):
            attach_native_crop_patch_plans(result, job, self.spec.name)
        return candidates_from_native_result(
            self.spec.name,
            result,
            job,
            diagnosis,
            native_key="native_archive_deep_repair",
            format_hint="7z",
            default_confidence=0.94,
            default_message="7z precise boundary repair produced a candidate",
            prefer_patch_plan=bool(config.get("virtual_patch_candidate")),
        )

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        return _native_seven_zip_precise_boundary_repair(
            source_input_for_job(job),
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            int(deep.get("max_candidates_per_module", 8) or 1),
        )


register_repair_module(SevenZipPreciseBoundaryRepair())
