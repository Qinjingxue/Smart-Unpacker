from dataclasses import dataclass
import struct
import zipfile
import zlib

from smart_unpacker.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from smart_unpacker.repair import RepairJob, RepairScheduler
from smart_unpacker.repair.pipeline.module import RepairModuleSpec
from smart_unpacker.repair.pipeline.registry import get_repair_module_registry
from smart_unpacker.repair.result import RepairResult


def test_repair_scheduler_without_modules_returns_unsupported(tmp_path):
    scheduler = RepairScheduler({"repair": {"workspace": str(tmp_path), "modules": []}})
    job = RepairJob(
        source_input={"kind": "file_range", "path": "mixed.bin", "start": 128},
        format="zip",
        confidence=0.62,
        damage_flags=["boundary_unreliable"],
        archive_key="mixed.zip",
    )

    result = scheduler.repair(job)

    assert result.status == "unsupported"
    assert result.format == "zip"
    assert result.diagnosis["categories"] == ["boundary_repair"]


def test_repair_diagnosis_combines_analysis_and_extraction_evidence(tmp_path):
    evidence = ArchiveFormatEvidence(
        format="zip",
        confidence=0.7,
        status="damaged",
        segments=[
            ArchiveSegment(
                start_offset=64,
                end_offset=None,
                confidence=0.7,
                damage_flags=["local_header_recovery", "boundary_unreliable"],
            )
        ],
    )
    scheduler = RepairScheduler({"repair": {"workspace": str(tmp_path)}})
    diagnosis = scheduler.diagnose(RepairJob(
        source_input={"kind": "file_range", "path": "carrier.bin", "start": 64},
        format="zip",
        confidence=0.55,
        analysis_evidence=evidence,
        extraction_failure={"checksum_error": True, "failed_item": "payload.bin"},
    ))

    assert diagnosis.format == "zip"
    assert diagnosis.start_trusted is True
    assert "boundary_repair" in diagnosis.categories
    assert "directory_rebuild" in diagnosis.categories
    assert "content_recovery" in diagnosis.categories


def test_repair_scheduler_runs_registered_module(tmp_path):
    module = _DummyBoundaryModule()
    registry = get_repair_module_registry()
    previous = registry.get(module.spec.name)
    registry.register(module)
    try:
        scheduler = RepairScheduler({
            "repair": {
                "workspace": str(tmp_path),
                "modules": [{"name": module.spec.name, "enabled": True}],
            }
        })
        result = scheduler.repair(RepairJob(
            source_input={"kind": "file_range", "path": "mixed.bin", "start": 10},
            format="zip",
            confidence=0.8,
            damage_flags=["boundary_unreliable"],
            archive_key="sample",
        ))
    finally:
        if previous is not None:
            registry.register(previous)

    assert result.ok is True
    assert result.module_name == module.spec.name
    assert result.repaired_input == {"kind": "file_range", "path": "mixed.bin", "start": 10, "end": 100}


def test_zip_central_directory_rebuild_repairs_missing_eocd(tmp_path):
    source = tmp_path / "missing_cd.zip"
    _write_zip(source, {"a.txt": b"alpha", "b.txt": b"bravo"})
    data = source.read_bytes()
    eocd_offset = data.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", data, eocd_offset + 16)[0]
    source.write_bytes(data[:cd_offset])

    result = _run_zip_repair(
        tmp_path,
        "zip_central_directory_rebuild",
        source,
        ["central_directory_bad"],
    )

    assert result.ok is True
    assert result.status == "repaired"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("a.txt") == b"alpha"
        assert archive.read("b.txt") == b"bravo"


def test_zip_partial_recovery_skips_damaged_entry(tmp_path):
    source = tmp_path / "partial.zip"
    _write_zip(source, {"bad.txt": b"broken", "good.txt": b"still here"})
    data = bytearray(source.read_bytes())
    first_lfh = data.find(b"PK\x03\x04")
    data[first_lfh:first_lfh + 4] = b"BAD!"
    source.write_bytes(bytes(data))

    result = _run_zip_repair(
        tmp_path,
        "zip_partial_recovery",
        source,
        ["damaged", "checksum_error"],
    )

    assert result.ok is True
    assert result.status == "partial"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.namelist() == ["good.txt"]
        assert archive.read("good.txt") == b"still here"


def test_zip_data_descriptor_recovery_materializes_sizes(tmp_path):
    source = tmp_path / "descriptor.zip"
    source.write_bytes(_descriptor_zip_fragment("dd.txt", b"descriptor payload"))

    result = _run_zip_repair(
        tmp_path,
        "zip_data_descriptor_recovery",
        source,
        ["data_descriptor", "compressed_size_bad"],
    )

    assert result.ok is True
    assert result.status == "repaired"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("dd.txt") == b"descriptor payload"


def test_zip_data_descriptor_recovery_supports_zip64_descriptor(tmp_path):
    source = tmp_path / "zip64_descriptor.zip"
    source.write_bytes(_descriptor_zip_fragment(
        "zip64-dd.txt",
        b"zip64 descriptor payload",
        zip64=True,
    ))

    result = _run_zip_repair(
        tmp_path,
        "zip_data_descriptor_recovery",
        source,
        ["data_descriptor", "compressed_size_bad"],
    )

    assert result.ok is True
    assert result.status == "repaired"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("zip64-dd.txt") == b"zip64 descriptor payload"


@dataclass
class _DummyBoundaryModule:
    spec = RepairModuleSpec(
        name="dummy_zip_boundary",
        formats=("zip",),
        categories=("boundary_repair",),
    )

    def can_handle(self, job, diagnosis, config):
        return 1.0 if "boundary_repair" in diagnosis.categories else 0.0

    def repair(self, job, diagnosis, workspace, config):
        return RepairResult(
            status="repaired",
            confidence=0.9,
            format=diagnosis.format,
            repaired_input={**job.source_input, "end": 100},
            actions=["dummy_boundary_trim"],
            module_name=self.spec.name,
            diagnosis=diagnosis.as_dict(),
            workspace_paths=[workspace],
        )


def _run_zip_repair(tmp_path, module_name, source, flags):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": module_name, "enabled": True}],
        }
    })
    return scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format="zip",
        confidence=0.7,
        damage_flags=flags,
        archive_key=source.name,
    ))


def _write_zip(path, files):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)


def _descriptor_zip_fragment(name: str, payload: bytes, *, zip64: bool = False) -> bytes:
    encoded_name = name.encode("utf-8")
    crc32 = zlib.crc32(payload) & 0xFFFFFFFF
    compressed_size = 0xFFFFFFFF if zip64 else 0
    uncompressed_size = 0xFFFFFFFF if zip64 else 0
    descriptor = (
        struct.pack("<IIQQ", 0x08074B50, crc32, len(payload), len(payload))
        if zip64
        else struct.pack("<IIII", 0x08074B50, crc32, len(payload), len(payload))
    )
    return b"".join([
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0x08,
            0,
            0,
            0,
            0,
            compressed_size,
            uncompressed_size,
            len(encoded_name),
            0,
        ),
        encoded_name,
        payload,
        descriptor,
        b"PK\x01\x02BROKEN-CENTRAL-DIR",
    ])
