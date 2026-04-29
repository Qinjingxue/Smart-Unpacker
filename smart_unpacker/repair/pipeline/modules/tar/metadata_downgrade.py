from __future__ import annotations

import io
import math
from pathlib import Path
import tarfile

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import load_job_source_bytes
from smart_unpacker.repair.pipeline.registry import register_repair_module
from smart_unpacker.repair.result import RepairResult


METADATA_TYPES = {b"x", b"g", b"L", b"K", b"S"}
REGULAR_TYPES = {b"0", b"\0", b""}


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
        data = load_job_source_bytes(job)
        recovered, skipped = _recover_tar_members(data)
        if not recovered or not skipped:
            return RepairResult(
                status="unrepairable",
                confidence=0.0,
                format="tar",
                module_name=self.spec.name,
                diagnosis=diagnosis.as_dict(),
                message="no TAR metadata member could be downgraded while preserving regular payloads",
            )
        output = Path(workspace) / "tar_metadata_downgrade_recovery.tar"
        output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output, mode="w") as archive:
            for name, payload in recovered:
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        confidence = min(0.92, 0.7 + 0.06 * len(recovered))
        return RepairResult(
            status="partial",
            confidence=confidence,
            format="tar",
            repaired_input={"kind": "file", "path": str(output), "format_hint": "tar"},
            actions=["walk_tar_headers", "drop_extended_metadata_headers", "rebuild_tar_regular_payloads"],
            damage_flags=list(job.damage_flags),
            warnings=[f"downgraded or skipped TAR metadata headers: {skipped[:8]}"],
            workspace_paths=[str(output)],
            partial=True,
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "tar_metadata_downgrade": {
                    "recovered_members": [name for name, _payload in recovered],
                    "skipped_metadata": skipped,
                },
            },
        )


def _recover_tar_members(data: bytes) -> tuple[list[tuple[str, bytes]], list[str]]:
    recovered: list[tuple[str, bytes]] = []
    skipped: list[str] = []
    offset = 0
    while offset + 512 <= len(data):
        header = data[offset:offset + 512]
        if header == b"\0" * 512:
            break
        size = _parse_octal(header[124:136])
        if size is None:
            skipped.append(f"invalid_header@{offset}")
            break
        payload_start = offset + 512
        payload_end = payload_start + size
        padded_end = payload_start + int(math.ceil(size / 512) * 512)
        if payload_end > len(data):
            skipped.append(f"truncated_member@{offset}")
            break
        typeflag = header[156:157]
        name = _tar_name(header)
        if typeflag in METADATA_TYPES:
            skipped.append(f"{typeflag.decode('ascii', errors='ignore') or 'metadata'}:{name or offset}")
        elif typeflag in REGULAR_TYPES and name:
            recovered.append((name, data[payload_start:payload_end]))
        offset = padded_end
    return recovered, skipped


def _tar_name(header: bytes) -> str:
    name = header[:100].split(b"\0", 1)[0].decode("utf-8", errors="replace").strip("/")
    prefix = header[345:500].split(b"\0", 1)[0].decode("utf-8", errors="replace").strip("/")
    return f"{prefix}/{name}" if prefix and name else name


def _parse_octal(value: bytes) -> int | None:
    text = value.strip(b"\0 ").decode("ascii", errors="ignore")
    if not text:
        return 0
    try:
        return int(text, 8)
    except ValueError:
        return None


register_repair_module(TarMetadataDowngradeRecovery())
