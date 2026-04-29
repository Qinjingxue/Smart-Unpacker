from __future__ import annotations

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import zip_deep_partial_recovery as _native_zip_deep_partial_recovery


class ZipEntryQuarantineRebuild:
    spec = RepairModuleSpec(
        name="zip_entry_quarantine_rebuild",
        formats=("zip",),
        categories=("content_recovery",),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("content_recovery",),
                require_any_flags=("damaged", "crc_error", "checksum_error", "payload_damaged", "entry_payload_bad"),
                reject_any_flags=("wrong_password", "data_descriptor", "duplicate_entries", "overlapping_entries", "local_header_conflict"),
                require_any_failure_kinds=("checksum_error", "corrupted_data", "data_error"),
                base_score=0.91,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"data_descriptor", "duplicate_entries", "overlapping_entries", "local_header_conflict"}:
            return 0.0
        coverage = coverage_view_from_job(job)
        if coverage.mixed_damage_suspected or coverage.payload_only_suspected:
            return 0.99
        if flags & {"crc_error", "checksum_error", "payload_damaged", "entry_payload_bad"}:
            return 0.98
        if "content_recovery" in diagnosis.categories:
            return 0.88
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(_native_zip_deep_partial_recovery(
            source_input_for_job(job),
            workspace,
            1,
            int(deep.get("max_entries", 20000) or 20000),
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_entry_uncompressed_mb", 512) or 0),
            float(deep.get("max_seconds_per_module", 30.0) or 0),
            True,
        ))
        selected_path = str(result.get("selected_path") or "")
        recovered = int(result.get("verified_entries") or result.get("recovered_entries") or 0)
        skipped = int(result.get("skipped_entries") or 0)
        if str(result.get("status") or "") not in {"repaired", "partial"} or not selected_path or not recovered or not skipped:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "native_zip_entry_quarantine": result},
                message="ZIP quarantine rebuild requires at least one good entry and one skipped damaged entry",
            )
        coverage = coverage_view_from_job(job)
        confidence = min(0.995, max(0.99, float(result.get("confidence") or 0.74) + coverage.score_hint(payload=0.04, mixed=0.04, partial=0.02)))
        return RepairResult(
            status="partial",
            confidence=confidence,
            format="zip",
            repaired_input={"kind": "file", "path": selected_path, "format_hint": "zip"},
            actions=list(result.get("actions") or ["deep_scan_local_headers", "verify_entry_payloads", "write_strict_verified_zip"]),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or [selected_path]),
            partial=True,
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "native_zip_entry_quarantine": result,
                "archive_coverage": coverage.as_dict(),
            },
            message="rebuilt ZIP from native-verified readable entries and quarantined damaged entries",
        )


register_repair_module(ZipEntryQuarantineRebuild())
