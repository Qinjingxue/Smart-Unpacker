import bz2
import gzip
import io
import lzma
import struct
import tarfile
import zlib

from sunpack.repair.diagnosis import diagnose_repair_job
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.modules.bzip2.atomic import Bzip2BlockSizeHeaderRepair
from sunpack.repair.pipeline.modules.gzip.atomic import GzipHeaderCrcRepair, GzipReservedFlagsRepair
from sunpack.repair.pipeline.modules.rar._structure import RAR5_MAGIC
from sunpack.repair.pipeline.modules.rar.atomic import RarMainHeaderCrcRepair
from sunpack.repair.pipeline.modules.tar.atomic import TarSingleHeaderChecksumRepair
from sunpack.repair.pipeline.modules.xz.atomic import XzStreamFooterCrcRepair, XzStreamHeaderCrcRepair
from sunpack.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry


def _job(data: bytes, fmt: str, flags: list[str], workspace) -> RepairJob:
    return RepairJob(
        source_input={"kind": "bytes", "data": data, "format_hint": fmt},
        format=fmt,
        damage_flags=flags,
        workspace=str(workspace),
    )


def _candidate_bytes(module, job: RepairJob, workspace) -> bytes:
    result = module.repair(job, diagnose_repair_job(job), str(workspace), {})
    assert result.ok
    assert result.repaired_input["kind"] == "file"
    with open(result.repaired_input["path"], "rb") as handle:
        return handle.read()


def test_registered_non_zip_formats_expose_only_atomic_actions():
    discover_repair_modules()
    registry = get_repair_module_registry().all()
    formats = {"rar", "tar", "gzip", "gz", "bzip2", "bz2", "xz", "zstd", "zst"}
    relevant = [module.spec for module in registry.values() if formats.intersection(module.spec.formats)]

    assert relevant
    assert all(spec.atomic for spec in relevant)
    assert all(spec.route_family for spec in relevant)
    assert "rar_file_quarantine_rebuild" not in registry
    assert "rar4_file_quarantine_rebuild" not in registry
    assert "tar_header_checksum_fix" not in registry
    assert "tar_metadata_downgrade_recovery" not in registry
    assert "tar_sparse_pax_longname_repair" not in registry


def test_rar5_main_header_crc_is_repaired_as_one_field_action(tmp_path):
    header_data = b"\x01\x00\x00"  # Main header, no common flags, no archive flags.
    damaged = RAR5_MAGIC + b"\x00\x00\x00\x00" + bytes([len(header_data)]) + header_data
    job = _job(damaged, "rar", ["rar_main_header_crc_bad"], tmp_path)

    repaired = _candidate_bytes(RarMainHeaderCrcRepair(), job, tmp_path)

    assert repaired[:8] == RAR5_MAGIC
    assert struct.unpack_from("<I", repaired, 8)[0] == zlib.crc32(repaired[12:16]) & 0xFFFFFFFF
    assert repaired[12:] == damaged[12:]


def test_gzip_header_crc_and_reserved_flags_are_separate_actions(tmp_path):
    raw = gzip.compress(b"payload")
    header = bytearray(raw[:10])
    header[3] |= 0x02
    damaged_crc = bytes(header) + b"\x00\x00" + raw[10:]
    crc_job = _job(damaged_crc, "gzip", ["gzip_header_crc_bad"], tmp_path / "crc")

    crc_repaired = _candidate_bytes(GzipHeaderCrcRepair(), crc_job, tmp_path / "crc")
    assert struct.unpack_from("<H", crc_repaired, 10)[0] == zlib.crc32(crc_repaired[:10]) & 0xFFFF
    assert gzip.decompress(crc_repaired) == b"payload"

    reserved = bytearray(raw)
    reserved[3] |= 0xE0
    flag_job = _job(bytes(reserved), "gzip", ["gzip_reserved_flags_set"], tmp_path / "flags")
    flag_repaired = _candidate_bytes(GzipReservedFlagsRepair(), flag_job, tmp_path / "flags")
    assert flag_repaired[3] & 0xE0 == 0
    assert gzip.decompress(flag_repaired) == b"payload"


def test_xz_header_and_footer_crc_repairs_are_independent(tmp_path):
    raw = lzma.compress(b"payload", format=lzma.FORMAT_XZ)
    bad_header = bytearray(raw)
    bad_header[8] ^= 0xFF
    header_job = _job(bytes(bad_header), "xz", ["xz_header_crc_bad"], tmp_path / "header")
    repaired_header = _candidate_bytes(XzStreamHeaderCrcRepair(), header_job, tmp_path / "header")
    assert lzma.decompress(repaired_header, format=lzma.FORMAT_XZ) == b"payload"

    bad_footer = bytearray(raw)
    bad_footer[-12] ^= 0xFF
    footer_job = _job(bytes(bad_footer), "xz", ["xz_footer_crc_bad"], tmp_path / "footer")
    repaired_footer = _candidate_bytes(XzStreamFooterCrcRepair(), footer_job, tmp_path / "footer")
    assert lzma.decompress(repaired_footer, format=lzma.FORMAT_XZ) == b"payload"


def test_bzip2_header_hypotheses_are_full_stream_validated(tmp_path):
    damaged = bytearray(bz2.compress(b"payload" * 128, compresslevel=9))
    damaged[3] = ord("0")
    job = _job(bytes(damaged), "bzip2", ["bzip2_block_size_bad"], tmp_path)

    repaired = _candidate_bytes(Bzip2BlockSizeHeaderRepair(), job, tmp_path)

    assert repaired[:3] == b"BZh"
    assert repaired[3:4] in b"123456789"
    assert bz2.decompress(repaired) == b"payload" * 128


def test_tar_checksum_repair_changes_only_one_member_header(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("payload.txt")
        payload = b"hello"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    damaged = bytearray(buffer.getvalue())
    damaged[148:156] = b"000000\0 "
    job = _job(bytes(damaged), "tar", ["tar_checksum_bad"], tmp_path)

    repaired = _candidate_bytes(TarSingleHeaderChecksumRepair(), job, tmp_path)

    assert repaired[:148] == damaged[:148]
    assert repaired[156:] == damaged[156:]
    with tarfile.open(fileobj=io.BytesIO(repaired), mode="r:") as archive:
        assert archive.extractfile("payload.txt").read() == b"hello"
