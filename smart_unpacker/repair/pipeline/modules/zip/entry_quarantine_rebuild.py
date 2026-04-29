from __future__ import annotations

from pathlib import Path
import zipfile

from smart_unpacker.repair.coverage import coverage_view_from_job
from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


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
                require_any_failure_kinds=("checksum_error", "corrupted_data", "data_error"),
                base_score=0.91,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        coverage = coverage_view_from_job(job)
        if coverage.mixed_damage_suspected or coverage.payload_only_suspected:
            return 0.99
        if flags & {"crc_error", "checksum_error", "payload_damaged", "entry_payload_bad"}:
            return 0.98
        if "content_recovery" in diagnosis.categories:
            return 0.88
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        source = Path(workspace) / "_zip_entry_quarantine_source.zip"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(load_job_source_bytes(job))
        output = Path(workspace) / "zip_entry_quarantine_rebuild.zip"
        password = str(job.password or "")
        recovered: list[str] = []
        skipped: list[str] = []
        try:
            with zipfile.ZipFile(source) as src, zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as dst:
                if password:
                    src.setpassword(password.encode("utf-8"))
                for info in src.infolist():
                    if info.is_dir():
                        continue
                    try:
                        payload = src.read(info)
                    except (OSError, RuntimeError, zipfile.BadZipFile, zlib_error()):
                        skipped.append(info.filename)
                        continue
                    clean = zipfile.ZipInfo(info.filename)
                    clean.date_time = info.date_time
                    clean.external_attr = info.external_attr
                    clean.comment = info.comment
                    clean.compress_type = zipfile.ZIP_STORED
                    dst.writestr(clean, payload)
                    recovered.append(info.filename)
        except (OSError, zipfile.BadZipFile) as exc:
            return RepairResult(status="unrepairable", confidence=0.0, format="zip", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message=f"ZIP entries could not be walked: {exc}")

        if not recovered or not skipped:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="zip",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="ZIP quarantine rebuild requires at least one good entry and one skipped damaged entry",
            )
        coverage = coverage_view_from_job(job)
        confidence = min(0.98, 0.74 + min(0.2, len(recovered) / max(1, len(recovered) + len(skipped)) * 0.2) + coverage.score_hint(payload=0.04, mixed=0.04, partial=0.02))
        return RepairResult(
            status="partial",
            confidence=confidence,
            format="zip",
            repaired_input={"kind": "file", "path": str(output), "format_hint": "zip"},
            actions=["read_zip_entries", "drop_failed_entries", "rebuild_zip_from_verified_payloads"],
            damage_flags=list(job.damage_flags),
            warnings=[f"quarantined damaged ZIP entries: {', '.join(skipped[:8])}"],
            workspace_paths=[str(source), str(output)],
            partial=True,
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "zip_entry_quarantine": {
                    "recovered_entries": recovered,
                    "skipped_entries": skipped,
                },
                "archive_coverage": coverage.as_dict(),
            },
            message="rebuilt ZIP from readable entries and quarantined damaged entries",
        )


def zlib_error():
    try:
        import zlib

        return zlib.error
    except Exception:
        return RuntimeError


register_repair_module(ZipEntryQuarantineRebuild())
