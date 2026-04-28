from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.result import RepairResult

from smart_unpacker_native import compression_stream_partial_recovery as _native_stream_partial_recovery


class CompressionStreamPartialRecovery:
    format_name: str = ""
    aliases: tuple[str, ...] = ()
    module_name: str = ""

    @property
    def spec(self) -> RepairModuleSpec:
        return RepairModuleSpec(
            name=self.module_name,
            formats=self.aliases,
            categories=("content_recovery", "boundary_repair"),
            stage="deep",
            safe=True,
            partial=True,
        )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {
            "probably_truncated",
            "stream_truncated",
            "input_truncated",
            "unexpected_end",
            "unexpected_eof",
            "data_error",
            "damaged",
        }:
            return 0.94
        if "content_recovery" in diagnosis.categories:
            return 0.84
        if "boundary_repair" in diagnosis.categories and flags & {"checksum_error", "crc_error"}:
            return 0.68
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = _native_stream_partial_recovery(
            job.source_input,
            self.format_name,
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_seconds_per_module", 30.0) or 0),
        )
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")
        if status != "partial" or not selected_path:
            return RepairResult(
                status="unrepairable" if status in {"skipped", "unsupported"} else status,
                confidence=float(result.get("confidence") or 0.0),
                format=self.format_name,
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or []),
                partial=True,
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message=str(result.get("message") or "compression stream partial recovery did not produce a candidate"),
            )

        return RepairResult(
            status="partial",
            confidence=float(result.get("confidence") or 0.62),
            format=self.format_name,
            repaired_input={"kind": "file", "path": selected_path, "format_hint": self.format_name},
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            partial=True,
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "native_stream_partial_recovery": {
                    "format": result.get("format", self.format_name),
                    "decoded_bytes": result.get("decoded_bytes", 0),
                    "output_bytes": result.get("output_bytes", 0),
                    "decoder_error": result.get("decoder_error", ""),
                },
            },
            message=str(result.get("message") or "compression stream partial recovery produced a candidate"),
        )
