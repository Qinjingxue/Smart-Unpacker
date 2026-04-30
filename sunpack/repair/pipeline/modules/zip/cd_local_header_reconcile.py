from __future__ import annotations

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack_native import zip_cd_local_header_reconcile_salvage as _native_zip_cd_local_header_reconcile_salvage

from ._entry_salvage import run_verified_entry_salvage


class ZipCdLocalHeaderReconcileRebuild:
    spec = RepairModuleSpec(
        name="zip_cd_local_header_reconcile_rebuild",
        formats=("zip",),
        categories=("directory_rebuild", "content_recovery"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "content_recovery"),
                require_any_flags=(
                    "central_directory_offset_bad",
                    "central_directory_bad",
                    "central_directory_count_bad",
                    "directory_integrity_bad_or_unknown",
                    "local_header_conflict",
                    "local_header_recovery",
                    "crc_error",
                    "checksum_error",
                ),
                require_any_failure_kinds=("structure_recognition", "corrupted_data", "checksum_error", "data_error"),
                base_score=0.94,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        coverage = coverage_view_from_job(job)
        if flags & {"local_header_conflict"}:
            return 0.98
        if "central_directory_offset_bad" in flags and flags & {"crc_error", "checksum_error", "damaged", "entry_payload_bad"}:
            return 0.82
        if "central_directory_offset_bad" in flags:
            return 0.9
        if flags & {"central_directory_bad", "directory_integrity_bad_or_unknown"} and coverage.has_payload_damage:
            return 0.96
        if flags & {"central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery"}:
            return 0.9
        if coverage.mixed_damage_suspected:
            return 0.88
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(_native_zip_cd_local_header_reconcile_salvage(
            source_input_for_job(job),
            workspace,
            int(deep.get("max_entries", 20000) or 20000),
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_entry_uncompressed_mb", 512) or 0),
            float(deep.get("max_seconds_per_module", 30.0) or 0),
        ))
        if str(result.get("status") or "") in {"repaired", "partial"} and result.get("selected_path"):
            coverage = coverage_view_from_job(job)
            return RepairResult(
                status="partial",
                confidence=min(0.995, 0.91 + coverage.score_hint(directory=0.04, mixed=0.04, partial=0.03)),
                format="zip",
                repaired_input={"kind": "file", "path": str(result.get("selected_path")), "format_hint": "zip"},
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or [str(result.get("selected_path"))]),
                partial=True,
                module_name=self.spec.name,
                diagnosis={
                    **diagnosis.as_dict(),
                    "archive_coverage": coverage.as_dict(),
                    "native_zip_cd_local_header_reconcile": result,
                },
                message="rebuilt ZIP after cross-checking central directory entries against physical local headers",
            )
        return run_verified_entry_salvage(
            module_name=self.spec.name,
            job=job,
            diagnosis=diagnosis,
            workspace=workspace,
            config=config,
            confidence=0.88,
            message="rebuilt ZIP from verified local headers after CD/local reconcile fallback",
        )


register_repair_module(ZipCdLocalHeaderReconcileRebuild())
