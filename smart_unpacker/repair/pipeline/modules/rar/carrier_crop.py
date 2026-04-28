from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules.archive_carrier_crop import _result_from_native
from smart_unpacker.repair.pipeline.registry import register_repair_module

from smart_unpacker_native import archive_carrier_crop_recovery as _native_archive_carrier_crop_recovery


class RarCarrierCropDeepRecovery:
    spec = RepairModuleSpec(
        name="rar_carrier_crop_deep_recovery",
        formats=("rar",),
        categories=("boundary_repair", "content_recovery", "directory_rebuild"),
        stage="deep",
        safe=True,
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "boundary_unreliable", "start_trusted_only"}:
            return 0.92
        if "boundary_repair" in diagnosis.categories:
            return 0.76
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = _native_archive_carrier_crop_recovery(
            job.source_input,
            "rar",
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            int(deep.get("max_candidates_per_module", 8) or 1),
        )
        return _result_from_native(self.spec.name, result, job, diagnosis, config)


register_repair_module(RarCarrierCropDeepRecovery())
