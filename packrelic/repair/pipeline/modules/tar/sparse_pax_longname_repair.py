from __future__ import annotations

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.module import RepairModuleSpec, RepairRoute
from packrelic.repair.pipeline.modules._common import source_input_for_job
from packrelic.repair.pipeline.registry import register_repair_module
from packrelic.repair.result import RepairResult
from packrelic_native import tar_sparse_pax_longname_repair as _native_tar_sparse_pax_repair


class TarSparsePaxLongnameRepair:
    spec = RepairModuleSpec(
        name="tar_sparse_pax_longname_repair",
        formats=("tar",),
        categories=("directory_rebuild", "content_recovery"),
        stage="targeted",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_categories=("directory_rebuild", "content_recovery"),
                require_any_flags=("gnu_longname_bad", "sparse_metadata_bad", "tar_size_bad", "damaged"),
                require_any_failure_kinds=("structure_recognition", "corrupted_data", "data_error"),
                base_score=0.82,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"gnu_longname_bad", "sparse_metadata_bad", "tar_size_bad"}:
            return 0.92
        if diagnosis.format == "tar" and flags & {"damaged", "corrupted_data"}:
            return 0.72
        if diagnosis.format == "tar" and "directory_rebuild" in diagnosis.categories:
            return 0.68
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(
            _native_tar_sparse_pax_repair(
                source_input_for_job(job),
                workspace,
                float(deep.get("max_input_size_mb", 512) or 0),
                float(deep.get("max_output_size_mb", 2048) or 0),
                int(deep.get("max_entries", 20000) or 20000),
            )
        )
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")
        if status in {"repaired", "partial"} and selected_path:
            return RepairResult(
                status="partial",
                confidence=float(result.get("confidence") or 0.78),
                format="tar",
                repaired_input={"kind": "file", "path": selected_path, "format_hint": "tar"},
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or [selected_path]),
                partial=True,
                module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "native_tar_sparse_pax_longname_repair": result},
                message=str(result.get("message") or "TAR sparse/PAX/GNU repair produced a candidate"),
            )
        return RepairResult(
            status="unrepairable" if status == "skipped" else status,
            confidence=float(result.get("confidence") or 0.0),
            format="tar",
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            module_name=self.spec.name,
            diagnosis={**diagnosis.as_dict(), "native_tar_sparse_pax_longname_repair": result},
            message=str(result.get("message") or "TAR sparse/PAX/GNU repair did not produce a candidate"),
        )


register_repair_module(TarSparsePaxLongnameRepair())
