from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._native_stream_trim import native_stream_trailing_trim_result
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult


_CONTENT_DAMAGE_FLAGS = {"checksum_error", "crc_error", "data_error", "damaged", "payload_damaged", "block_damaged"}


class Bzip2TrailingJunkTrim:
    spec = RepairModuleSpec(
        name="bzip2_trailing_junk_trim",
        formats=("bzip2", "bz2"),
        categories=("boundary_repair",),
        stage="safe_repair",
        atomic=True,
        route_family="bzip2_stream_boundary_trim",
        routes=(
            RepairRoute(
                formats=("bzip2", "bz2"),
                require_any_categories=("boundary_repair",),
                require_any_flags=("trailing_junk", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "trailing_padding_likely"),
                reject_any_flags=tuple(sorted(_CONTENT_DAMAGE_FLAGS)),
                base_score=0.72,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & _CONTENT_DAMAGE_FLAGS:
            return 0.0
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.84
        if "boundary_repair" in diagnosis.categories:
            return 0.58
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        return native_stream_trailing_trim_result(
            module_name=self.spec.name,
            fmt="bzip2",
            job=job,
            diagnosis=diagnosis,
            workspace=workspace,
            config=config,
        )


register_repair_module(Bzip2TrailingJunkTrim())
