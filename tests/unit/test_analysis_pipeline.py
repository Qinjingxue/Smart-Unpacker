import time
import tarfile
import zipfile
import bz2
import gzip
import lzma
from binascii import crc32
from io import BytesIO

from smart_unpacker.analysis.pipeline.module import AnalysisModuleSpec
from smart_unpacker.analysis.pipeline.registry import get_analysis_module_registry
from smart_unpacker.analysis.result import ArchiveFormatEvidence
from smart_unpacker.analysis.scheduler import ArchiveAnalysisScheduler
from smart_unpacker.analysis.view import SharedBinaryView


def _zip_bytes(tmp_path):
    archive = tmp_path / "inner.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("marker.txt", "hello")
    return archive.read_bytes()


def _rar4_block(header_type: int, flags: int = 0, payload: bytes = b"") -> bytes:
    add_size = len(payload).to_bytes(4, "little") if payload else b""
    header_size = 7 + len(add_size)
    body = bytes([header_type]) + flags.to_bytes(2, "little") + header_size.to_bytes(2, "little") + add_size
    header_crc = (crc32(body) & 0xFFFF).to_bytes(2, "little")
    return header_crc + body + payload


def _rar4_bytes() -> bytes:
    return b"Rar!\x1a\x07\x00" + _rar4_block(0x73) + _rar4_block(0x7B)


def _rar5_vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _rar5_block(header_type: int, flags: int = 0, data: bytes = b"") -> bytes:
    fields = _rar5_vint(header_type) + _rar5_vint(flags)
    if data:
        flags |= 0x0002
        fields = _rar5_vint(header_type) + _rar5_vint(flags) + _rar5_vint(len(data))
    header_size = _rar5_vint(len(fields))
    header_data = header_size + fields
    return crc32(header_data).to_bytes(4, "little") + header_data + data


def _rar5_bytes() -> bytes:
    return b"Rar!\x1a\x07\x01\x00" + _rar5_block(1) + _rar5_block(5)


def _seven_zip_bytes() -> bytes:
    gap = b"abcde"
    next_header = b"\x01"
    start_header = len(gap).to_bytes(8, "little") + len(next_header).to_bytes(8, "little") + crc32(next_header).to_bytes(4, "little")
    return b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + crc32(start_header).to_bytes(4, "little") + start_header + gap + next_header


def _write_bytes(path, data: bytes):
    path.write_bytes(data)
    return path


def _tar_bytes() -> bytes:
    buffer = BytesIO()
    payload = b"tar payload"
    info = tarfile.TarInfo("payload.txt")
    info.size = len(payload)
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        tf.addfile(info, BytesIO(payload))
    return buffer.getvalue()


def test_analysis_scheduler_finds_embedded_archive_segments(tmp_path):
    zip_start = len(b"shell-a")
    zip_data = _zip_bytes(tmp_path)
    rar_data = _rar4_bytes()
    payload = (
        b"shell-a"
        + zip_data
        + b"shell-b"
        + rar_data
        + b"shell-c"
    )
    path = tmp_path / "mixed.bin"
    path.write_bytes(payload)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    by_format = {item.format: item for item in report.evidences}

    assert by_format["zip"].status == "extractable"
    assert by_format["zip"].confidence == 0.99
    assert by_format["zip"].segments[0].start_offset == zip_start
    assert by_format["zip"].segments[0].end_offset == zip_start + len(zip_data)
    assert by_format["rar"].status == "extractable"
    assert by_format["rar"].confidence == 0.97
    assert by_format["rar"].segments[0].start_offset == payload.index(b"Rar!")
    assert by_format["rar"].segments[0].end_offset == payload.index(b"Rar!") + len(rar_data)
    assert by_format["7z"].status == "not_found"
    assert by_format["7z"].confidence == 0.0
    assert {item.format for item in report.selected} == {"zip", "rar"}


def test_zip_embedded_local_header_without_eocd_keeps_embedded_start(tmp_path):
    zip_data = _zip_bytes(tmp_path)
    payload = b"MZstub" + zip_data[:40]
    path = tmp_path / "zip_sfx_split_head.exe"
    path.write_bytes(payload)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    zip_evidence = {item.format: item for item in report.evidences}["zip"]

    assert zip_evidence.status == "not_found"
    assert zip_evidence.segments == []


def test_zip_crc_mismatch_marks_content_integrity(tmp_path):
    data = bytearray(_zip_bytes(tmp_path))
    data[14] ^= 0xFF
    path = _write_bytes(tmp_path / "crc_bad.zip", bytes(data))

    zip_evidence = {item.format: item for item in ArchiveAnalysisScheduler().analyze_path(str(path)).evidences}["zip"]

    assert zip_evidence.status == "extractable"
    assert "content_integrity_bad_or_unknown" in zip_evidence.segments[0].damage_flags
    assert zip_evidence.details["integrity_confidence"] == "low"


def test_zip_bad_central_directory_recovers_from_local_header(tmp_path):
    data = bytearray(_zip_bytes(tmp_path))
    cd_offset = data.index(b"PK\x01\x02")
    data[cd_offset:cd_offset + 2] = b"XX"
    path = _write_bytes(tmp_path / "cd_bad.zip", bytes(data))

    zip_evidence = {item.format: item for item in ArchiveAnalysisScheduler().analyze_path(str(path)).evidences}["zip"]

    assert zip_evidence.status == "damaged"
    assert zip_evidence.confidence == 0.70
    assert zip_evidence.segments[0].end_offset is None
    assert "local_header_recovery" in zip_evidence.segments[0].damage_flags
    assert zip_evidence.details["recovery_strategy"] == "local_header_scan"


def test_analysis_scheduler_prefers_structural_boundary_over_next_signature(tmp_path):
    rar_data = _rar4_bytes()
    seven_data = _seven_zip_bytes()
    payload = b"shell" + rar_data + b"noise" + seven_data
    path = tmp_path / "mixed.bin"
    path.write_bytes(payload)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    by_format = {item.format: item for item in report.evidences}

    assert by_format["rar"].segments[0].end_offset == len(b"shell") + len(rar_data)
    assert by_format["7z"].segments[0].start_offset == payload.index(b"7z\xbc\xaf\x27\x1c")
    assert by_format["7z"].confidence == 0.97


def test_analysis_scheduler_walks_rar4_blocks_to_endarc(tmp_path):
    rar_data = _rar4_bytes()
    payload = b"shell" + rar_data + b"tail-shell"
    path = tmp_path / "rar4.bin"
    path.write_bytes(payload)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    rar = {item.format: item for item in report.evidences}["rar"]

    assert rar.status == "extractable"
    assert rar.confidence == 0.97
    assert rar.segments[0].start_offset == len(b"shell")
    assert rar.segments[0].end_offset == len(b"shell") + len(rar_data)
    assert not rar.warnings
    assert rar.details["end_block_found"] is True


def test_analysis_scheduler_walks_rar5_blocks_to_endarc(tmp_path):
    rar_data = _rar5_bytes()
    payload = b"shell" + rar_data + b"tail-shell"
    path = tmp_path / "rar5.bin"
    path.write_bytes(payload)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    rar = {item.format: item for item in report.evidences}["rar"]

    assert rar.status == "extractable"
    assert rar.confidence == 0.97
    assert rar.segments[0].start_offset == len(b"shell")
    assert rar.segments[0].end_offset == len(b"shell") + len(rar_data)
    assert not rar.warnings
    assert rar.details["version"] == 5
    assert rar.details["end_block_found"] is True


def test_rar_missing_end_block_is_probably_truncated(tmp_path):
    rar_data = _rar5_bytes()[:-len(_rar5_block(5))]
    path = _write_bytes(tmp_path / "truncated.rar", rar_data)

    rar = {item.format: item for item in ArchiveAnalysisScheduler().analyze_path(str(path)).evidences}["rar"]

    assert rar.status == "damaged"
    assert rar.confidence == 0.82
    assert rar.segments[0].end_offset is None
    assert "probably_truncated" in rar.segments[0].damage_flags
    assert rar.details["boundary_confidence"] == "low"


def test_rar_missing_main_header_marks_encrypted_unwalkable(tmp_path):
    rar_data = b"Rar!\x1a\x07\x01\x00" + _rar5_block(4)
    path = _write_bytes(tmp_path / "header_encrypted_like.rar", rar_data)

    rar = {item.format: item for item in ArchiveAnalysisScheduler().analyze_path(str(path)).evidences}["rar"]

    assert rar.status == "damaged"
    assert rar.confidence == 0.72
    assert rar.segments[0].end_offset is None
    assert "valid_encrypted_but_unwalkable" in rar.segments[0].damage_flags
    assert rar.details["password_required"] is True


def test_analysis_scheduler_uses_7z_start_header_for_segment_end(tmp_path):
    seven_data = _seven_zip_bytes()
    payload = b"shell" + seven_data + b"tail-shell"
    path = tmp_path / "seven.bin"
    path.write_bytes(payload)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    seven = {item.format: item for item in report.evidences}["7z"]

    assert seven.status == "extractable"
    assert seven.confidence == 0.97
    assert seven.segments[0].start_offset == len(b"shell")
    assert seven.segments[0].end_offset == len(b"shell") + len(seven_data)
    assert not seven.warnings
    assert seven.details["next_header_crc_ok"] is True


def test_7z_start_header_damage_leaves_only_start_trusted(tmp_path):
    seven_data = bytearray(_seven_zip_bytes())
    seven_data[8] ^= 0xFF
    path = _write_bytes(tmp_path / "start_crc_bad.7z", bytes(seven_data))

    seven = {item.format: item for item in ArchiveAnalysisScheduler().analyze_path(str(path)).evidences}["7z"]

    assert seven.status == "weak"
    assert seven.segments[0].start_offset == 0
    assert seven.segments[0].end_offset is None
    assert "boundary_unreliable" in seven.segments[0].damage_flags
    assert seven.details["boundary_confidence"] == "none"


def test_7z_next_header_crc_damage_keeps_boundary_but_lowers_integrity(tmp_path):
    seven_data = bytearray(_seven_zip_bytes())
    next_offset = int.from_bytes(seven_data[12:20], "little")
    seven_data[32 + next_offset] ^= 0xFF
    path = _write_bytes(tmp_path / "next_crc_bad.7z", bytes(seven_data))

    seven = {item.format: item for item in ArchiveAnalysisScheduler().analyze_path(str(path)).evidences}["7z"]

    assert seven.status == "damaged"
    assert seven.segments[0].end_offset == len(seven_data)
    assert "directory_integrity_bad_or_unknown" in seven.segments[0].damage_flags
    assert seven.details["integrity_confidence"] == "low"


def test_analysis_scheduler_reads_zip_across_split_volumes(tmp_path):
    zip_data = _zip_bytes(tmp_path)
    first = tmp_path / "archive.zip.001"
    second = tmp_path / "archive.zip.002"
    first.write_bytes(zip_data[:37])
    second.write_bytes(zip_data[37:])

    report = ArchiveAnalysisScheduler().analyze_paths([str(first), str(second)])
    zip_evidence = {item.format: item for item in report.evidences}["zip"]

    assert zip_evidence.status == "extractable"
    assert zip_evidence.confidence == 0.99
    assert zip_evidence.segments[0].start_offset == 0
    assert zip_evidence.segments[0].end_offset == len(zip_data)


def test_analysis_scheduler_reads_7z_across_split_volumes(tmp_path):
    seven_data = _seven_zip_bytes()
    first = tmp_path / "archive.7z.001"
    second = tmp_path / "archive.7z.002"
    first.write_bytes(seven_data[:20])
    second.write_bytes(seven_data[20:])

    report = ArchiveAnalysisScheduler().analyze_paths([str(first), str(second)])
    seven = {item.format: item for item in report.evidences}["7z"]

    assert seven.status == "extractable"
    assert seven.confidence == 0.97
    assert seven.segments[0].start_offset == 0
    assert seven.segments[0].end_offset == len(seven_data)


def test_analysis_scheduler_detects_tar(tmp_path):
    tar_data = _tar_bytes()
    path = _write_bytes(tmp_path / "payload.tar", tar_data)

    report = ArchiveAnalysisScheduler().analyze_path(str(path))
    tar = {item.format: item for item in report.evidences}["tar"]

    assert tar.status == "extractable"
    assert tar.confidence >= 0.86
    assert tar.segments[0].start_offset == 0
    assert tar.segments[0].end_offset is not None
    assert tar.details["entry_walk_ok"] is True


def test_analysis_scheduler_detects_compression_streams(tmp_path):
    samples = {
        "gzip": (tmp_path / "payload.gz", gzip.compress(b"plain payload")),
        "bzip2": (tmp_path / "payload.bz2", bz2.compress(b"plain payload")),
        "xz": (tmp_path / "payload.xz", lzma.compress(b"plain payload", format=lzma.FORMAT_XZ)),
        "zstd": (tmp_path / "payload.zst", b"\x28\xb5\x2f\xfd\x20\x00"),
    }

    for fmt, (path, data) in samples.items():
        path.write_bytes(data)
        evidence = {item.format: item for item in ArchiveAnalysisScheduler().analyze_path(str(path)).evidences}[fmt]
        assert evidence.status == "extractable"
        assert evidence.confidence >= 0.88
        assert evidence.segments[0].start_offset == 0


def test_analysis_scheduler_detects_compressed_tar_variants(tmp_path):
    tar_data = _tar_bytes()
    samples = {
        "tar.gz": (tmp_path / "payload.tar.gz", gzip.compress(tar_data)),
        "tar.bz2": (tmp_path / "payload.tar.bz2", bz2.compress(tar_data)),
        "tar.xz": (tmp_path / "payload.tar.xz", lzma.compress(tar_data, format=lzma.FORMAT_XZ)),
    }

    for fmt, (path, data) in samples.items():
        path.write_bytes(data)
        evidence = {item.format: item for item in ArchiveAnalysisScheduler().analyze_path(str(path)).evidences}[fmt]
        assert evidence.status == "extractable"
        assert evidence.confidence >= 0.93
        assert evidence.details["inner_tar_verified"] is True


def test_tar_zst_requires_real_zstd_inner_tar(tmp_path):
    path = tmp_path / "payload.tar.zst"
    path.write_bytes(b"\x28\xb5\x2f\xfd\x20\x00")

    evidence = {item.format: item for item in ArchiveAnalysisScheduler().analyze_path(str(path)).evidences}["tar.zst"]

    assert evidence.status == "not_found"
    assert evidence.details["tar_probe_error"]


def test_analysis_module_config_can_disable_formats(tmp_path):
    path = tmp_path / "payload.bin"
    path.write_bytes(_zip_bytes(tmp_path) + b"Rar!\x1a\x07\x00")

    report = ArchiveAnalysisScheduler({
        "analysis": {
            "modules": [
                {"name": "zip", "enabled": True},
                {"name": "rar", "enabled": False},
                {"name": "seven_zip", "enabled": False},
            ],
        },
    }).analyze_path(str(path))

    assert [item.format for item in report.evidences] == ["zip"]


def test_shared_binary_view_reuses_cached_reads(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abcdef")
    view = SharedBinaryView(str(path), cache_bytes=1024)

    assert view.read_at(0, 3) == b"abc"
    assert view.read_at(0, 3) == b"abc"

    stats = view.stats()
    assert stats.read_bytes == 3
    assert stats.cache_hits == 1


def test_shared_binary_view_enforces_read_budget(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abcdef")
    view = SharedBinaryView(str(path), cache_bytes=0, max_read_bytes=2)

    try:
        view.read_at(0, 3)
    except RuntimeError as exc:
        assert "read budget" in str(exc)
    else:
        raise AssertionError("read budget should be enforced")


class _SlowModule:
    def __init__(self, name: str):
        self.spec = AnalysisModuleSpec(name=name, formats=(name,), signatures=(name.encode("ascii"),))

    def analyze(self, view, prepass, config):
        time.sleep(0.15)
        return ArchiveFormatEvidence(format=self.spec.name, confidence=0.0, status="not_found")


def test_analysis_scheduler_runs_modules_in_parallel(tmp_path):
    registry = get_analysis_module_registry()
    first = _SlowModule("slow_a")
    second = _SlowModule("slow_b")
    registry.register(first)
    registry.register(second)
    path = tmp_path / "slow.bin"
    path.write_bytes(b"slow_a slow_b")

    start = time.perf_counter()
    ArchiveAnalysisScheduler({
        "analysis": {
            "parallel": True,
            "max_workers": 2,
            "modules": [
                {"name": "slow_a", "enabled": True},
                {"name": "slow_b", "enabled": True},
            ],
        },
    }).analyze_path(str(path))
    elapsed = time.perf_counter() - start

    assert elapsed < 0.28
