from dataclasses import dataclass
import gzip
import io
import lzma
import tarfile
import struct
import zipfile
import zlib

import pytest

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


def test_zip_eocd_repair_rebuilds_missing_eocd_from_central_directory(tmp_path):
    source = tmp_path / "missing_eocd.zip"
    _write_zip(source, {"payload.txt": b"zip payload"})
    data = source.read_bytes()
    source.write_bytes(data[:data.rfind(b"PK\x05\x06")])

    result = _run_repair(tmp_path, "zip_eocd_repair", "zip", source, ["eocd_bad", "central_directory_bad"])

    assert result.ok is True
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("payload.txt") == b"zip payload"


def test_zip_central_directory_offset_fix_rewrites_bad_eocd_offset(tmp_path):
    source = tmp_path / "bad_cd_offset.zip"
    _write_zip(source, {"payload.txt": b"zip payload"})
    data = bytearray(source.read_bytes())
    eocd_offset = bytes(data).rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, eocd_offset + 16, 0)
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "zip_central_directory_offset_fix", "zip", source, ["central_directory_offset_bad"])

    assert result.ok is True
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("payload.txt") == b"zip payload"


def test_zip_trailing_junk_trim_removes_bytes_after_eocd(tmp_path):
    source = tmp_path / "zip_tail.zip"
    _write_zip(source, {"payload.txt": b"zip payload"})
    original = source.read_bytes()
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "zip_trailing_junk_trim", "zip", source, ["trailing_junk"])

    assert result.ok is True
    assert result.repaired_input["path"]
    assert len(open(result.repaired_input["path"], "rb").read()) == len(original)


def test_tar_header_checksum_fix_rewrites_bad_checksum(tmp_path):
    source = tmp_path / "bad_checksum.tar"
    source.write_bytes(_tar_bytes({"payload.txt": b"tar payload"}))
    data = bytearray(source.read_bytes())
    data[148:156] = b"000000\0 "
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "tar_header_checksum_fix", "tar", source, ["tar_checksum_bad"])

    assert result.ok is True
    with tarfile.open(result.repaired_input["path"]) as archive:
        assert archive.extractfile("payload.txt").read() == b"tar payload"


def test_tar_trailing_zero_block_repair_appends_missing_end_blocks(tmp_path):
    source = tmp_path / "missing_zeros.tar"
    full = _tar_bytes({"payload.txt": b"tar payload"})
    source.write_bytes(full[:1024])

    result = _run_repair(tmp_path, "tar_trailing_zero_block_repair", "tar", source, ["missing_end_block"])

    assert result.ok is True
    with tarfile.open(result.repaired_input["path"]) as archive:
        assert archive.extractfile("payload.txt").read() == b"tar payload"


def test_gzip_footer_fix_rewrites_crc_and_isize(tmp_path):
    source = tmp_path / "bad_footer.gz"
    data = bytearray(gzip.compress(b"gzip payload"))
    data[-8:] = b"\0" * 8
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "gzip_footer_fix", "gzip", source, ["gzip_footer_bad"])

    assert result.ok is True
    assert gzip.decompress(open(result.repaired_input["path"], "rb").read()) == b"gzip payload"


def test_xz_trailing_junk_trim_removes_bytes_after_stream(tmp_path):
    source = tmp_path / "tail.xz"
    original = lzma.compress(b"xz payload", format=lzma.FORMAT_XZ)
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "xz_trailing_junk_trim", "xz", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original


def test_zstd_trailing_junk_trim_removes_bytes_after_stream_when_backend_available(tmp_path):
    zstd = pytest.importorskip("zstandard")
    source = tmp_path / "tail.zst"
    original = zstd.ZstdCompressor().compress(b"zstd payload")
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "zstd_trailing_junk_trim", "zstd", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original


def test_seven_zip_boundary_trim_removes_bytes_after_next_header(tmp_path):
    source = tmp_path / "tail.7z"
    original = _seven_zip_bytes()
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "seven_zip_boundary_trim", "7z", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original


def test_seven_zip_start_header_crc_fix_rewrites_bad_crc(tmp_path):
    source = tmp_path / "bad_start_crc.7z"
    data = bytearray(_seven_zip_bytes())
    data[8:12] = b"\0\0\0\0"
    source.write_bytes(bytes(data))

    result = _run_repair(tmp_path, "seven_zip_start_header_crc_fix", "7z", source, ["start_header_crc_bad"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == _seven_zip_bytes()


def test_rar_trailing_junk_trim_supports_rar4(tmp_path):
    source = tmp_path / "tail4.rar"
    original = _rar4_bytes()
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "rar_trailing_junk_trim", "rar", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original


def test_rar_trailing_junk_trim_supports_rar5(tmp_path):
    source = tmp_path / "tail5.rar"
    original = _rar5_bytes()
    source.write_bytes(original + b"JUNK")

    result = _run_repair(tmp_path, "rar_trailing_junk_trim", "rar", source, ["trailing_junk"])

    assert result.ok is True
    assert open(result.repaired_input["path"], "rb").read() == original


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
    return _run_repair(tmp_path, module_name, "zip", source, flags)


def _run_repair(tmp_path, module_name, fmt, source, flags):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": module_name, "enabled": True}],
        }
    })
    return scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format=fmt,
        confidence=0.7,
        damage_flags=flags,
        archive_key=source.name,
    ))


def _write_zip(path, files):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)


def _tar_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


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


def _seven_zip_bytes() -> bytes:
    next_header = b"\x01"
    gap = b"abcde"
    start_header = struct.pack("<QQI", len(gap), len(next_header), zlib.crc32(next_header) & 0xFFFFFFFF)
    return b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + struct.pack("<I", zlib.crc32(start_header) & 0xFFFFFFFF) + start_header + gap + next_header


def _rar4_block(header_type: int, flags: int = 0, payload: bytes = b"") -> bytes:
    add_size = len(payload).to_bytes(4, "little") if payload else b""
    header_size = 7 + len(add_size)
    body = bytes([header_type]) + flags.to_bytes(2, "little") + header_size.to_bytes(2, "little") + add_size
    header_crc = (zlib.crc32(body) & 0xFFFF).to_bytes(2, "little")
    return header_crc + body + payload


def _rar4_bytes() -> bytes:
    return b"Rar!\x1a\x07\x00" + _rar4_block(0x73) + _rar4_block(0x7B)


def _rar5_vint(value: int) -> bytes:
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            output.append(byte | 0x80)
        else:
            output.append(byte)
            return bytes(output)


def _rar5_block(header_type: int, flags: int = 0, data: bytes = b"") -> bytes:
    fields = _rar5_vint(header_type) + _rar5_vint(flags)
    if data:
        flags |= 0x0002
        fields = _rar5_vint(header_type) + _rar5_vint(flags) + _rar5_vint(len(data))
    header_size = _rar5_vint(len(fields))
    header_data = header_size + fields
    return zlib.crc32(header_data).to_bytes(4, "little") + header_data + data


def _rar5_bytes() -> bytes:
    return b"Rar!\x1a\x07\x01\x00" + _rar5_block(1) + _rar5_block(5)
