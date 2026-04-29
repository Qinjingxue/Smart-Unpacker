from __future__ import annotations

import io
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import zipfile
import zlib

import pytest

from sunpack.repair import RepairJob, RepairScheduler
from sunpack.support.sevenzip_worker import dry_run_archive
from tests.helpers.real_archives import ArchiveFixtureFactory, apply_split_issue
from tests.helpers.tool_config import get_optional_rar


RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"


def test_zip_conflict_resolver_keeps_best_duplicate_entry(tmp_path):
    good_payload = b"good duplicate payload"
    bad = _raw_stored_local_entry("dup.txt", b"bad payload", crc32=0)
    good = _raw_stored_local_entry("dup.txt", good_payload)
    source = tmp_path / "conflicted.zip"
    source.write_bytes(bad + good + b"tail")

    result = _run_deep_module(
        tmp_path,
        "zip_conflict_resolver_rebuild",
        "zip",
        source,
        ["duplicate_entries", "overlapping_entries", "damaged"],
    )

    assert result.status == "partial"
    assert result.module_name == "zip_conflict_resolver_rebuild"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.namelist() == ["dup.txt"]
        assert archive.read("dup.txt") == good_payload


def test_archive_nested_payload_salvage_extracts_inner_zip(tmp_path):
    inner_entries = {"inner.txt": b"nested payload"}
    inner_zip = _zip_bytes(inner_entries)
    source = tmp_path / "damaged-outer.bin"
    source.write_bytes(b"broken outer header" + inner_zip + b"broken tail")

    result = _run_deep_module(
        tmp_path,
        "archive_nested_payload_salvage",
        "zip",
        source,
        ["outer_container_bad", "nested_archive", "damaged"],
    )

    assert result.status == "partial"
    assert result.module_name == "archive_nested_payload_salvage"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("inner.txt") == inner_entries["inner.txt"]


def test_tar_sparse_pax_longname_repair_drops_metadata_and_preserves_payload(tmp_path):
    long_name = "very/" + "deep/" * 18 + "payload.txt"
    payload = b"tar payload after longname"
    source = tmp_path / "pax-longname.tar"
    source.write_bytes(
        _tar_header("././@LongLink", len(long_name) + 1, b"L")
        + (long_name.encode("utf-8") + b"\0").ljust(512, b"\0")
        + _tar_header("short.txt", len(payload), b"0")
        + payload.ljust(512, b"\0")
        + (b"\0" * 1024)
    )

    result = _run_module(
        tmp_path,
        "tar_sparse_pax_longname_repair",
        "tar",
        source,
        ["gnu_longname_bad", "pax_header_bad"],
    )

    assert result.status == "partial"
    assert result.module_name == "tar_sparse_pax_longname_repair"
    with tarfile.open(result.repaired_input["path"]) as archive:
        member = archive.extractfile(long_name)
        assert member is not None
        assert member.read() == payload


def test_rar_file_quarantine_rebuild_keeps_complete_rar5_file_block(tmp_path):
    payload = b"rar payload"
    source = tmp_path / "rar5-quarantine.rar"
    complete_prefix = RAR5_MAGIC + _rar5_block(1) + _rar5_block(2, data=payload)
    source.write_bytes(complete_prefix + b"BROKEN-RAR5-BLOCK")

    result = _run_deep_module(
        tmp_path,
        "rar_file_quarantine_rebuild",
        "rar",
        source,
        ["file_block_bad", "damaged", "data_error"],
    )

    repaired = Path(result.repaired_input["path"]).read_bytes()
    assert result.status == "partial"
    assert result.module_name == "rar_file_quarantine_rebuild"
    assert repaired.startswith(RAR5_MAGIC)
    assert payload in repaired
    assert repaired.endswith(_rar5_block(5))
    assert b"BROKEN-RAR5-BLOCK" not in repaired


def test_rar_file_quarantine_rebuild_resyncs_damaged_split_volume(tmp_path):
    if get_optional_rar() is None:
        pytest.skip("RAR generator is not configured")
    case = ArchiveFixtureFactory().create(
        tmp_path / "fixtures",
        "rar_split_quarantine",
        "rar",
        split=True,
        payload_size=180 * 1024,
    )
    apply_split_issue(case, "corrupt_member")
    parts = sorted(str(path) for path in case.archive_dir.iterdir() if path.is_file())
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "stages": {"deep": True},
            "modules": [{"name": "rar_file_quarantine_rebuild", "enabled": True}],
        }
    })

    result = scheduler.repair(RepairJob(
        source_input={
            "kind": "concat_ranges",
            "ranges": [{"path": path, "start": 0} for path in parts],
            "format_hint": "rar",
        },
        format="rar",
        confidence=0.97,
        damage_flags=["damaged", "file_block_bad", "data_error"],
        extraction_failure={"failure_kind": "structure_recognition", "decision_hint": "repair"},
        archive_key=case.case_id,
    ))

    assert result.status == "partial"
    assert result.module_name == "rar_file_quarantine_rebuild"
    dry_run = dry_run_archive(result.repaired_input["path"], format_hint="rar", timeout=10)
    assert dry_run.ok
    assert int(dry_run.result.get("files_written", 0) or 0) >= 1


def test_seven_zip_solid_block_partial_salvage_repackages_decodable_entries_as_zip(tmp_path):
    seven_zip = _require_7z_tool()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "alpha.txt").write_bytes(b"alpha 7z payload")
    (source_dir / "bravo.txt").write_bytes(b"bravo 7z payload")
    source = tmp_path / "solid.7z"
    subprocess.run(
        [str(seven_zip), "a", "-t7z", "-ms=on", str(source), str(source_dir / "*")],
        cwd=str(tmp_path),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    result = _run_deep_module(
        tmp_path,
        "seven_zip_solid_block_partial_salvage",
        "7z",
        source,
        ["solid_block_damaged", "packed_stream_bad", "damaged"],
    )

    assert result.status == "partial"
    assert result.module_name == "seven_zip_solid_block_partial_salvage"
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert archive.read("alpha.txt") == b"alpha 7z payload"
        assert archive.read("bravo.txt") == b"bravo 7z payload"


def _run_module(tmp_path: Path, module_name: str, fmt: str, source: Path, flags: list[str]):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "modules": [{"name": module_name, "enabled": True}],
        }
    })
    return scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format=fmt,
        confidence=0.82,
        damage_flags=flags,
        archive_key=source.name,
    ))


def _run_deep_module(tmp_path: Path, module_name: str, fmt: str, source: Path, flags: list[str]):
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair"),
            "stages": {"deep": True},
            "deep": {"verify_candidates": False, "max_candidates_per_module": 4},
            "modules": [{"name": module_name, "enabled": True}],
        }
    })
    return scheduler.repair(RepairJob(
        source_input={"kind": "file", "path": str(source)},
        format=fmt,
        confidence=0.82,
        damage_flags=flags,
        archive_key=source.name,
    ))


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def _raw_stored_local_entry(name: str, payload: bytes, *, crc32: int | None = None) -> bytes:
    encoded = name.encode("utf-8")
    crc = zlib.crc32(payload) & 0xFFFFFFFF if crc32 is None else crc32
    return (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(encoded),
            0,
        )
        + encoded
        + payload
    )


def _tar_header(name: str, size: int, typeflag: bytes) -> bytes:
    header = bytearray(512)
    encoded = name.encode("utf-8")
    header[: min(len(encoded), 100)] = encoded[:100]
    _write_octal(header, 100, 8, 0o644)
    _write_octal(header, 108, 8, 0)
    _write_octal(header, 116, 8, 0)
    _write_octal(header, 124, 12, size)
    _write_octal(header, 136, 12, 0)
    header[148:156] = b"        "
    header[156:157] = typeflag
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(header)


def _write_octal(header: bytearray, offset: int, width: int, value: int) -> None:
    raw = f"{value:0{width - 1}o}\0".encode("ascii")
    header[offset: offset + width] = raw


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
    header_data = _rar5_vint(len(fields)) + fields
    return zlib.crc32(header_data).to_bytes(4, "little") + header_data + data


def _require_7z_tool() -> Path:
    candidate = Path("tools") / "7z.exe"
    if candidate.is_file():
        return candidate.resolve()
    found = shutil.which("7z")
    if found:
        return Path(found)
    pytest.skip("7z executable is required for 7z salvage fixture")
