from __future__ import annotations

import gzip
from pathlib import Path
import zlib

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


GZIP_MEMBER_MAGIC = b"\x1f\x8b\x08"


class GzipDeflateMemberResync:
    spec = RepairModuleSpec(
        name="gzip_deflate_member_resync",
        formats=("gzip", "gz"),
        categories=("content_recovery",),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("gzip", "gz"),
                require_any_categories=("content_recovery",),
                require_any_flags=("deflate_resync", "damaged", "checksum_error", "data_error"),
                require_any_failure_kinds=("corrupted_data", "data_error", "checksum_error"),
                base_score=0.86,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"deflate_resync", "damaged", "checksum_error", "data_error"}:
            return 0.92
        if "content_recovery" in diagnosis.categories:
            return 0.78
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        data = load_job_source_bytes(job)
        offsets = _member_offsets(data)
        if len(offsets) < 2:
            return RepairResult(status="unrepairable", confidence=0.0, format="gzip", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="gzip deflate resync requires multiple member headers")
        recovered: list[bytes] = []
        recovered_offsets: list[int] = []
        skipped_offsets: list[int] = []
        for index, start in enumerate(offsets):
            end = offsets[index + 1] if index + 1 < len(offsets) else len(data)
            try:
                payload = gzip.decompress(data[start:end])
            except (OSError, EOFError, zlib.error):
                skipped_offsets.append(start)
                continue
            recovered.append(payload)
            recovered_offsets.append(start)
        if not recovered or not skipped_offsets:
            return RepairResult(status="unrepairable", confidence=0.0, format="gzip", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no damaged gzip member could be skipped while preserving a later member")
        output = Path(workspace) / "gzip_deflate_member_resync.gz"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(gzip.compress(b"".join(recovered)))
        confidence = min(0.9, 0.64 + 0.1 * len(recovered))
        return RepairResult(
            status="partial",
            confidence=confidence,
            format="gzip",
            repaired_input={"kind": "file", "path": str(output), "format_hint": "gzip"},
            actions=["scan_gzip_members", "skip_bad_deflate_members", "recompress_recovered_payload"],
            damage_flags=list(job.damage_flags),
            warnings=[f"skipped damaged gzip member offsets: {skipped_offsets[:8]}"],
            workspace_paths=[str(output)],
            partial=True,
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "gzip_deflate_member_resync": {
                    "member_candidates": offsets,
                    "recovered_offsets": recovered_offsets,
                    "skipped_offsets": skipped_offsets,
                    "recovered_bytes": sum(len(item) for item in recovered),
                },
            },
        )


def _member_offsets(data: bytes) -> list[int]:
    offsets = []
    pos = data.find(GZIP_MEMBER_MAGIC)
    while pos >= 0:
        offsets.append(pos)
        pos = data.find(GZIP_MEMBER_MAGIC, pos + 1)
    return offsets


register_repair_module(GzipDeflateMemberResync())
