from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.modules.archive_carrier_crop import _result_from_native
from smart_unpacker.repair.pipeline.registry import register_repair_module

from smart_unpacker_native import rar_end_block_repair as _native_rar_end_block_repair


class RarEndBlockRepair:
    spec = RepairModuleSpec(
        name="rar_end_block_repair",
        formats=("rar",),
        categories=("boundary_repair",),
        stage="deep",
        safe=True,
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"missing_end_block", "probably_truncated", "unexpected_end", "boundary_unreliable"}:
            return 0.84
        if "boundary_repair" in diagnosis.categories:
            return 0.68
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = _native_rar_end_block_repair(
            job.source_input,
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            int(deep.get("max_candidates_per_module", 8) or 1),
        )
        return _result_from_native(self.spec.name, result, job, diagnosis, config)


register_repair_module(RarEndBlockRepair())
