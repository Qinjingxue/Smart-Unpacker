from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.registry import register_repair_module

from ._boundary import TarBoundaryRepairModule


class TarTrailingJunkTrim(TarBoundaryRepairModule):
    spec = RepairModuleSpec(
        name="tar_trailing_junk_trim",
        formats=("tar",),
        categories=("boundary_repair",),
        stage="safe_repair",
        atomic=True,
        route_family="tar_boundary_trim",
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_categories=("boundary_repair",),
                require_any_flags=("trailing_junk", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "trailing_padding_likely", "tail_printable_region"),
                base_score=0.72,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.84
        if diagnosis.format == "tar" and "boundary_repair" in diagnosis.categories:
            return 0.62
        return 0.0

register_repair_module(TarTrailingJunkTrim())
