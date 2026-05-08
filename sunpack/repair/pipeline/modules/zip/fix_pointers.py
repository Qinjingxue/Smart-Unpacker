from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job, module_limits
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import zip_directory_field_repair as _native_zip_directory_field_repair

from ._native_field_result import repair_result_from_native_zip_field


class ZipFixPointers:
    spec = RepairModuleSpec(
        name="zip_fix_pointers",
        formats=("zip",),
        categories=("directory_rebuild", "boundary_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "boundary_repair"),
                require_any_flags=(
                    "central_directory_offset_bad", "central_directory_count_bad",
                    "central_directory_bad", "eocd_bad", "directory_integrity_bad_or_unknown",
                    "local_header_bad", "local_header_length_bad", "local_header_size_bad",
                ),
                require_any_failure_kinds=("structure_recognition", "corrupted_data"),
                base_score=0.82,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.0
        score = 0.0
        content_damage = flags & {"checksum_error", "crc_error", "entry_payload_bad", "damaged", "content_integrity_bad_or_unknown", "data_error"}
        if "eocd_bad" in flags:
            score = 0.97
        elif flags & {"central_directory_offset_bad", "central_directory_count_bad", "central_directory_bad"}:
            score = 0.90
        elif flags & {"local_header_bad", "local_header_length_bad", "local_header_size_bad"}:
            score = 0.88
        elif flags & {"directory_integrity_bad_or_unknown"}:
            score = 0.85
        if content_damage and score > 0:
            score = max(0.30, score - 0.40)
        return score

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        flags = set(job.damage_flags)
        limits = module_limits(config)

        if "eocd_bad" in flags:
            repair_name = "zip_eocd_repair"
        elif flags & {"central_directory_offset_bad"}:
            repair_name = "zip_central_directory_offset_fix"
        elif flags & {"central_directory_count_bad"}:
            repair_name = "zip_central_directory_count_fix"
        elif flags & {"local_header_bad", "local_header_length_bad", "local_header_size_bad"}:
            repair_name = "zip_local_header_field_repair"
        else:
            repair_name = "zip_eocd_repair"

        result = _native_zip_directory_field_repair(
            source_input_for_job(job), workspace, repair_name,
            float(limits.get("max_input_size_mb", 512) or 0),
        )
        return repair_result_from_native_zip_field(self.spec.name, dict(result), job, diagnosis, config)


# Legacy coarse module kept for historical imports only. ZIP repair registration
# now happens through atomic.py.
