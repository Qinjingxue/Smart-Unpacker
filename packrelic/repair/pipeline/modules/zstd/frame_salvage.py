from __future__ import annotations

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.module import RepairModuleSpec, RepairRoute
from packrelic.repair.pipeline.modules._common import source_input_for_job
from packrelic.repair.pipeline.registry import register_repair_module
from packrelic.repair.result import RepairResult
from packrelic_native import zstd_frame_salvage_repair as _native_zstd_frame_salvage


class ZstdFrameSalvage:
    spec = RepairModuleSpec(
        name="zstd_frame_salvage",
        formats=("zstd", "zst"),
        categories=("content_recovery",),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("zstd", "zst"),
                require_any_categories=("content_recovery",),
                require_any_flags=("frame_damaged", "damaged", "checksum_error", "data_error"),
                require_any_failure_kinds=("corrupted_data", "data_error", "checksum_error"),
                base_score=0.88,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"frame_damaged", "damaged", "checksum_error", "data_error"}:
            return 0.94
        if "content_recovery" in diagnosis.categories:
            return 0.82
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(
            _native_zstd_frame_salvage(
                source_input_for_job(job),
                workspace,
                float(deep.get("max_input_size_mb", 512) or 0),
                float(deep.get("max_output_size_mb", 2048) or 0),
            )
        )
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")
        if status == "partial" and selected_path:
            return RepairResult(
                status="partial",
                confidence=float(result.get("confidence") or 0.0),
                format="zstd",
                repaired_input={"kind": "file", "path": selected_path, "format_hint": "zstd"},
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or [selected_path]),
                partial=True,
                module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "native_zstd_frame_salvage": result},
                message=str(result.get("message") or "native zstd frame salvage produced a candidate"),
            )
        return RepairResult(
            status="unrepairable" if status in {"skipped", "unsupported"} else status,
            confidence=float(result.get("confidence") or 0.0),
            format="zstd",
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            module_name=self.spec.name,
            diagnosis={**diagnosis.as_dict(), "native_zstd_frame_salvage": result},
            message=str(result.get("message") or "native zstd frame salvage did not produce a candidate"),
        )


register_repair_module(ZstdFrameSalvage())
