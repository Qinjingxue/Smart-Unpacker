from __future__ import annotations

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.pipeline.module import RepairModuleSpec, RepairRoute
from packrelic.repair.pipeline.modules._common import source_input_for_job
from packrelic.repair.pipeline.registry import register_repair_module
from packrelic.repair.result import RepairResult
from packrelic_native import rar_block_chain_trim_recovery as _native_rar_block_chain_trim


class RarTrailingJunkTrim:
    spec = RepairModuleSpec(
        name="rar_trailing_junk_trim",
        formats=("rar",),
        categories=("boundary_repair",),
        stage="safe_repair",
        routes=(
            RepairRoute(
                formats=("rar",),
                require_any_categories=("boundary_repair",),
                require_any_flags=("trailing_junk", "boundary_unreliable", "trailing_padding"),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "trailing_padding_likely"),
                reject_any_flags=(
                    "carrier_archive",
                    "sfx",
                    "embedded_archive",
                    "carrier_prefix",
                    "missing_end_block",
                    "probably_truncated",
                ),
                base_score=0.76,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix", "missing_end_block", "probably_truncated"}:
            return 0.0
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.84
        if "boundary_repair" in diagnosis.categories:
            return 0.68
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(
            _native_rar_block_chain_trim(
                source_input_for_job(job),
                workspace,
                float(deep.get("max_input_size_mb", 512) or 0),
                int(deep.get("max_candidates_per_module", 8) or 1),
            )
        )
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")
        if status in {"repaired", "partial"} and selected_path:
            return RepairResult(
                status=status,
                confidence=float(result.get("confidence") or 0.86),
                format="rar",
                repaired_input={"kind": "file", "path": selected_path, "format_hint": "rar"},
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or [selected_path]),
                partial=status == "partial",
                module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "native_rar_block_chain_trim": result},
                message=str(result.get("message") or "native RAR trailing trim produced a candidate"),
            )
        return RepairResult(
            status="unrepairable" if status in {"skipped", "unsupported"} else status,
            confidence=float(result.get("confidence") or 0.0),
            format="rar",
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            module_name=self.spec.name,
            diagnosis={**diagnosis.as_dict(), "native_rar_block_chain_trim": result},
            message=str(result.get("message") or "native RAR trailing trim did not produce a candidate"),
        )


register_repair_module(RarTrailingJunkTrim())
