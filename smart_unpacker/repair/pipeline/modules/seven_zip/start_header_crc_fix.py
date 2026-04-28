from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
import struct

from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes, patch_plan_for_byte_patches, patch_repair_result
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult

from ._structure import parse_start_header, rewrite_start_crc


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
        data = load_job_source_bytes(job)
        header = parse_start_header(data)
        if header is None:
            return RepairResult(status="unrepairable", confidence=0.0, format="7z", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="7z start header fields are not safely parseable")
        if header.start_crc_ok:
            return RepairResult(status="unrepairable", confidence=0.0, format="7z", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="7z start header CRC is already valid")
        warnings = [] if header.next_header_crc_ok else ["next header CRC is still invalid after start header CRC repair"]
        confidence = 0.86 if header.next_header_crc_ok else 0.62
        actions = ["recompute_7z_start_header_crc"]
        patch = {"offset": 8, "data": struct.pack("<I", header.computed_start_crc)}
        patch_plan = patch_plan_for_byte_patches(job, self.spec.name, [patch], confidence=confidence, actions=actions)
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
            filename="seven_zip_start_header_crc_fix.7z",
            config=config,
            materialized_data=rewrite_start_crc(data, header),
        )


register_repair_module(SevenZipStartHeaderCrcFix())
