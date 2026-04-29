from __future__ import annotations

from pathlib import Path

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


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
        try:
            import zstandard as zstd
        except ImportError as exc:
            return RepairResult(status="unsupported", confidence=0.0, format="zstd", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message=f"zstandard backend is not available: {exc}")

        data = load_job_source_bytes(job)
        offsets = _frame_offsets(data)
        if len(offsets) < 2:
            return RepairResult(status="unrepairable", confidence=0.0, format="zstd", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="zstd frame salvage requires multiple frame candidates")

        recovered_payloads: list[bytes] = []
        recovered_offsets: list[int] = []
        skipped_offsets: list[int] = []
        for index, start in enumerate(offsets):
            end = offsets[index + 1] if index + 1 < len(offsets) else len(data)
            segment = data[start:end]
            try:
                payload = zstd.ZstdDecompressor().decompress(segment)
            except zstd.ZstdError:
                skipped_offsets.append(start)
                continue
            recovered_payloads.append(payload)
            recovered_offsets.append(start)

        if not recovered_payloads or not skipped_offsets:
            return RepairResult(status="unrepairable", confidence=0.0, format="zstd", module_name=self.spec.name, diagnosis=diagnosis.as_dict(), message="no damaged zstd frame could be skipped while preserving a good frame")

        output = Path(workspace) / "zstd_frame_salvage.zst"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(zstd.ZstdCompressor(level=0).compress(b"".join(recovered_payloads)))
        confidence = min(0.94, 0.68 + 0.12 * len(recovered_payloads))
        return RepairResult(
            status="partial",
            confidence=confidence,
            format="zstd",
            repaired_input={"kind": "file", "path": str(output), "format_hint": "zstd"},
            actions=["scan_zstd_frames", "skip_bad_frames", "recompress_recovered_payload"],
            damage_flags=list(job.damage_flags),
            warnings=[f"skipped damaged zstd frame offsets: {skipped_offsets[:8]}"],
            workspace_paths=[str(output)],
            partial=True,
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "zstd_frame_salvage": {
                    "frame_candidates": offsets,
                    "recovered_offsets": recovered_offsets,
                    "skipped_offsets": skipped_offsets,
                    "recovered_bytes": sum(len(item) for item in recovered_payloads),
                },
            },
        )


def _frame_offsets(data: bytes) -> list[int]:
    offsets = []
    pos = data.find(ZSTD_MAGIC)
    while pos >= 0:
        offsets.append(pos)
        pos = data.find(ZSTD_MAGIC, pos + 1)
    return offsets


register_repair_module(ZstdFrameSalvage())
