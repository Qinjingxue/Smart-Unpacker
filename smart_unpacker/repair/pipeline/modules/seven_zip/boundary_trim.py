from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute

from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes, patch_plan_for_truncate, patch_repair_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._structure import parse_start_header


class SevenZipBoundaryTrim:
    spec = RepairModuleSpec(
        name="seven_zip_boundary_trim",
        formats=("7z", "seven_zip"),
        categories=("boundary_repair",),
        stage="safe_repair",
        routes=(
            RepairRoute(
                formats=("7z", "seven_zip"),
                require_any_categories=("boundary_repair",),
                require_any_flags=("trailing_junk", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "trailing_padding_likely"),
                base_score=0.78,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.86
        if "boundary_repair" in diagnosis.categories:
            return 0.7
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        header = parse_start_header(data)
        if header is None or not header.start_crc_ok:
            return RepairResult(status="unrepairable", confidence=0.0, format="7z", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="7z boundary is not trusted without a valid start header")
        if header.archive_end == len(data):
            return RepairResult(status="unrepairable", confidence=0.0, format="7z", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no trailing bytes after 7z archive end")
        warnings = [] if header.next_header_crc_ok else ["next header CRC is invalid; trim only repaired outer boundary"]
        confidence = 0.9 if header.next_header_crc_ok else 0.68
        actions = ["trim_after_7z_next_header"]
        patch_plan = patch_plan_for_truncate(job, self.spec.name, header.archive_end, confidence=confidence, actions=actions)
        return patch_repair_result(
            job=job,
            diagnosis=diagnosis,
            module_name=self.spec.name,
            fmt="7z",
            patch_plan=patch_plan,
            confidence=confidence,
            actions=actions,
            warnings=warnings,
            workspace=workspace,
            filename="seven_zip_boundary_trim.7z",
            config=config,
            materialized_data=data[:header.archive_end],
        )


register_repair_module(SevenZipBoundaryTrim())
