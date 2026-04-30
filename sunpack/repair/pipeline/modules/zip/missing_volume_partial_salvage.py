from __future__ import annotations

from dataclasses import replace

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import zip_deep_partial_recovery as _native_zip_deep_partial_recovery


class ZipMissingVolumePartialSalvage:
    spec = RepairModuleSpec(
        name="zip_missing_volume_partial_salvage",
        formats=("zip",),
        categories=("content_recovery", "directory_rebuild", "boundary_repair"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("content_recovery", "directory_rebuild", "boundary_repair"),
                require_any_flags=("missing_volume", "local_header_recovery"),
                require_any_failure_kinds=("unexpected_end", "input_truncated", "structure_recognition", "data_error"),
                reject_any_flags=("wrong_password", "carrier_archive", "sfx", "embedded_archive", "carrier_prefix", "duplicate_entries", "overlapping_entries", "local_header_conflict"),
                base_score=0.9,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"wrong_password", "carrier_archive", "sfx", "embedded_archive", "carrier_prefix", "duplicate_entries", "overlapping_entries", "local_header_conflict"}:
            return 0.0
        if "missing_volume" in flags and "local_header_recovery" in flags:
            return 0.96
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        result = self._run_native(job, workspace, config)
        candidates = self._candidates_from_native(result, job, diagnosis)
        if not candidates:
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
                diagnosis={**diagnosis.as_dict(), "native_zip_missing_volume_partial_salvage": result},
                message=str(result.get("message") or "ZIP missing-volume partial salvage did not produce a candidate"),
            )
        return candidates[0].to_result(selection={"selected_module": self.spec.name})

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        return self._candidates_from_native(self._run_native(job, workspace, config), job, diagnosis)

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        return dict(_native_zip_deep_partial_recovery(
            source_input_for_job(job),
            workspace,
            int(deep.get("max_candidates_per_module", 3) or 3),
            int(deep.get("max_entries", 20000) or 20000),
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_entry_uncompressed_mb", 512) or 0),
            float(deep.get("max_seconds_per_module", 30.0) or 0),
            bool(deep.get("verify_candidates", True)),
        ))

    def _candidates_from_native(self, result: dict, job: RepairJob, diagnosis: RepairDiagnosis):
        coverage = coverage_view_from_job(job)
        candidates = candidates_from_native_result(
            self.spec.name,
            result,
            job,
            diagnosis,
            native_key="native_zip_missing_volume_partial_salvage",
            format_hint="zip",
            partial_default=True,
            default_confidence=0.68,
            default_message="ZIP missing-volume partial salvage produced a candidate",
        )
        return [
            replace(
                candidate,
                confidence=min(0.98, float(candidate.confidence or 0.0) + coverage.score_hint(directory=0.02, partial=0.04)),
                diagnosis={
                    **candidate.diagnosis,
                    "archive_coverage": coverage.as_dict(),
                    "coverage_strategy": "missing_volume_local_header_salvage",
                },
            )
            for candidate in candidates
            if int(candidate.diagnosis.get("native_candidate", {}).get("verified_entries") or 0) > 0
        ]


register_repair_module(ZipMissingVolumePartialSalvage())
