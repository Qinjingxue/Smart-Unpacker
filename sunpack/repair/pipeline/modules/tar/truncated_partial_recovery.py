from __future__ import annotations

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import tar_truncated_partial_recovery as _native_tar_truncated_partial_recovery


class TarTruncatedPartialRecovery:
    spec = RepairModuleSpec(
        name="tar_truncated_partial_recovery",
        formats=("tar",),
        categories=("content_recovery", "boundary_repair"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("tar",),
                require_any_categories=("content_recovery", "boundary_repair"),
                require_any_flags=("input_truncated", "probably_truncated", "unexpected_end", "damaged"),
                require_any_failure_kinds=("unexpected_end", "input_truncated", "stream_truncated", "data_error"),
                base_score=0.86,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"input_truncated", "probably_truncated", "unexpected_end"}:
            return 0.92
        if diagnosis.format == "tar" and {"content_recovery", "boundary_repair"} & set(diagnosis.categories):
            return 0.72
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(_native_tar_truncated_partial_recovery(
            source_input_for_job(job),
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            int(deep.get("max_entries", 20000) or 20000),
        ))
        status = str(result.get("status") or "unrepairable")
        if status not in {"repaired", "partial"} or not result.get("selected_path"):
            return RepairResult(
                status="unrepairable" if status in {"skipped", "unsupported"} else status,
                confidence=float(result.get("confidence") or 0.0),
                format="tar",
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or []),
                partial=True,
                module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "native_tar_truncated_partial_recovery": result},
                message=str(result.get("message") or "TAR truncated partial recovery did not produce a candidate"),
            )
        return RepairResult(
            status="partial",
            confidence=float(result.get("confidence") or 0.68),
            format="tar",
            repaired_input={"kind": "file", "path": str(result["selected_path"]), "format_hint": "tar"},
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            partial=True,
            module_name=self.spec.name,
            diagnosis={**diagnosis.as_dict(), "native_tar_truncated_partial_recovery": result},
            message=str(result.get("message") or "TAR truncated partial recovery produced a candidate"),
        )


register_repair_module(TarTruncatedPartialRecovery())
