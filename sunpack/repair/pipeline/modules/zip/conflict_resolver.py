from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import zip_conflict_resolver_rebuild as _native_zip_conflict_resolver


class ZipConflictResolverRebuild:
    spec = RepairModuleSpec(
        name="zip_conflict_resolver_rebuild",
        formats=("zip",),
        categories=("directory_rebuild", "content_recovery"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "content_recovery"),
                require_any_flags=("duplicate_entries", "overlapping_entries", "local_header_conflict"),
                require_any_failure_kinds=("structure_recognition", "corrupted_data", "checksum_error"),
                base_score=0.9,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"duplicate_entries", "overlapping_entries", "local_header_conflict"}:
            return 0.96
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        result = self._run_native(job, workspace, config)
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")
        if status in {"repaired", "partial"} and selected_path:
            return RepairResult(
                status="partial",
                confidence=float(result.get("confidence") or 0.74),
                format="zip",
                repaired_input={"kind": "file", "path": selected_path, "format_hint": "zip"},
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or [selected_path]),
                partial=True,
                module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "native_zip_conflict_resolver": result},
                message=str(result.get("message") or "ZIP conflict resolver produced a clean candidate"),
            )
        return RepairResult(
            status="unrepairable" if status == "skipped" else status,
            confidence=float(result.get("confidence") or 0.0),
            format="zip",
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            module_name=self.spec.name,
            diagnosis={**diagnosis.as_dict(), "native_zip_conflict_resolver": result},
            message=str(result.get("message") or "ZIP conflict resolver did not produce a candidate"),
        )

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        return candidates_from_native_result(
            self.spec.name,
            result,
            job,
            diagnosis,
            native_key="native_zip_conflict_resolver",
            format_hint="zip",
            partial_default=True,
            default_confidence=0.74,
            default_message="ZIP conflict resolver produced a candidate",
        )

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        return dict(
            _native_zip_conflict_resolver(
                source_input_for_job(job),
                workspace,
                int(deep.get("max_entries", 20000) or 20000),
                float(deep.get("max_input_size_mb", 512) or 0),
                float(deep.get("max_output_size_mb", 2048) or 0),
                float(deep.get("max_entry_uncompressed_mb", 512) or 0),
                bool(deep.get("verify_candidates", True)),
            )
        )


register_repair_module(ZipConflictResolverRebuild())
