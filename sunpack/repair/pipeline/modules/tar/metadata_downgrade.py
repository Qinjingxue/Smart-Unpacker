from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import tar_metadata_downgrade_recovery as _native_tar_metadata_downgrade_recovery


class TarMetadataDowngradeRecovery:
    spec = RepairModuleSpec(
        name="tar_metadata_downgrade_recovery",
        formats=("tar",),
        categories=("content_recovery", "directory_rebuild"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_categories=("content_recovery", "directory_rebuild"),
                require_any_flags=("pax_header_bad", "gnu_longname_bad", "sparse_header_bad", "tar_metadata_bad", "tar_checksum_bad"),
                require_any_failure_kinds=("corrupted_data", "structure_recognition"),
                base_score=0.84,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"pax_header_bad", "gnu_longname_bad", "sparse_header_bad", "tar_metadata_bad"}:
            return 0.94
        if "directory_rebuild" in diagnosis.categories and "tar_checksum_bad" in flags:
            return 0.58
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(_native_tar_metadata_downgrade_recovery(
            source_input_for_job(job),
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            int(deep.get("max_entries", 20000) or 20000),
        ))
        selected_path = str(result.get("selected_path") or "")
        status = str(result.get("status") or "unrepairable")
        if status not in {"partial", "repaired"} or not selected_path:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="tar",
                module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "native_tar_metadata_downgrade": result},
                message="no TAR metadata member could be downgraded while preserving regular payloads",
            )
        return RepairResult(
            status="partial",
            confidence=float(result.get("confidence") or 0.72),
            format="tar",
            repaired_input={"kind": "file", "path": selected_path, "format_hint": "tar"},
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or [selected_path]),
            partial=True,
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "native_tar_metadata_downgrade": result,
            },
        )


register_repair_module(TarMetadataDowngradeRecovery())
