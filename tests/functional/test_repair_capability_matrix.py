from __future__ import annotations

import bz2
from dataclasses import dataclass, field
import gzip
import io
import lzma
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
from typing import Callable
import zipfile
import zlib

import pytest

from sunpack.repair import RepairJob, RepairResult, RepairScheduler


VerifyFn = Callable[[RepairResult, "MatrixFixture"], None]
BuildFn = Callable[[Path], "MatrixFixture"]


@dataclass(frozen=True)
class MatrixFixture:
    source_input: dict
    expected_bytes: bytes | None = None
    zip_entries: dict[str, bytes] = field(default_factory=dict)
    tar_entries: dict[str, bytes] = field(default_factory=dict)
    stream_payload: bytes | None = None


@dataclass(frozen=True)
class MatrixCase:
    case_id: str
    fmt: str
    flags: tuple[str, ...]
    build: BuildFn
    expected_statuses: tuple[str, ...]
    expected_module: str | None
    verify: VerifyFn | None = None
    modules: tuple[str, ...] = ()


@dataclass(frozen=True)
class RepairRound:
    flags: tuple[str, ...]
    expected_statuses: tuple[str, ...]
    expected_module: str
    modules: tuple[str, ...] = ()


@dataclass(frozen=True)
class MultiRoundCase:
    case_id: str
    fmt: str
    build: BuildFn
    rounds: tuple[RepairRound, ...]
    verify: VerifyFn


def _run_matrix_repair(tmp_path: Path, case: MatrixCase, fixture: MatrixFixture) -> RepairResult:
    scheduler = _repair_scheduler(tmp_path, modules=case.modules)
    return scheduler.repair(RepairJob(
        source_input=fixture.source_input,
        format=case.fmt,
        confidence=0.82,
        damage_flags=list(case.flags),
        archive_key=case.case_id,
    ))


def _repair_scheduler(tmp_path: Path, *, modules: tuple[str, ...] = ()) -> RepairScheduler:
    repair_config = {
        "workspace": str(tmp_path / "repair-workspace"),
        "max_modules_per_job": 8,
        "stages": {"deep": True},
        "deep": {
            "max_candidates_per_module": 4,
            "verify_candidates": False,
        },
    }
    if modules:
        repair_config["modules"] = [{"name": name, "enabled": True} for name in modules]
    return RepairScheduler({
        "repair": {
            **repair_config,
        }
    })


def _fixture_from_bytes(root: Path, name: str, data: bytes, **kwargs) -> MatrixFixture:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_bytes(data)
    return MatrixFixture(source_input={"kind": "file", "path": str(path)}, **kwargs)


def _fixture_from_ranges(root: Path, name: str, data: bytes, split_at: int, **kwargs) -> MatrixFixture:
    root.mkdir(parents=True, exist_ok=True)
    first = root / f"{name}.001"
    second = root / f"{name}.002"
    first.write_bytes(data[:split_at])
    second.write_bytes(data[split_at:])
    return MatrixFixture(
        source_input={
            "kind": "concat_ranges",
            "ranges": [
                {"path": str(first), "start": 0, "end": first.stat().st_size},
                {"path": str(second), "start": 0, "end": second.stat().st_size},
            ],
        },
        **kwargs,
    )


def _verify_bytes(result: RepairResult, fixture: MatrixFixture) -> None:
    assert Path(result.repaired_input["path"]).read_bytes() == fixture.expected_bytes


def _verify_zip(result: RepairResult, fixture: MatrixFixture) -> None:
    with zipfile.ZipFile(result.repaired_input["path"]) as archive:
        assert sorted(archive.namelist()) == sorted(fixture.zip_entries)
        for name, payload in fixture.zip_entries.items():
            assert archive.read(name) == payload


def _verify_tar(result: RepairResult, fixture: MatrixFixture) -> None:
    with tarfile.open(result.repaired_input["path"]) as archive:
        assert sorted(item.name for item in archive.getmembers() if item.isfile()) == sorted(fixture.tar_entries)
        for name, payload in fixture.tar_entries.items():
            member = archive.extractfile(name)
            assert member is not None
            assert member.read() == payload


def _verify_gzip(result: RepairResult, fixture: MatrixFixture) -> None:
    assert gzip.decompress(Path(result.repaired_input["path"]).read_bytes()) == fixture.stream_payload


def _verify_bzip2(result: RepairResult, fixture: MatrixFixture) -> None:
    assert bz2.decompress(Path(result.repaired_input["path"]).read_bytes()) == fixture.stream_payload


def _verify_xz(result: RepairResult, fixture: MatrixFixture) -> None:
    assert lzma.decompress(Path(result.repaired_input["path"]).read_bytes()) == fixture.stream_payload


def _verify_zstd(result: RepairResult, fixture: MatrixFixture) -> None:
    zstd = pytest.importorskip("zstandard")
    assert _zstd_decompress_all(zstd, Path(result.repaired_input["path"]).read_bytes()) == fixture.stream_payload


def _verify_gzip_prefix(result: RepairResult, fixture: MatrixFixture) -> None:
    recovered = gzip.decompress(Path(result.repaired_input["path"]).read_bytes())
    assert fixture.stream_payload is not None
    assert fixture.stream_payload.startswith(recovered)
    assert 0 < len(recovered) < len(fixture.stream_payload)


def _verify_bzip2_prefix(result: RepairResult, fixture: MatrixFixture) -> None:
    recovered = bz2.decompress(Path(result.repaired_input["path"]).read_bytes())
    assert fixture.stream_payload is not None
    assert fixture.stream_payload.startswith(recovered)
    assert 0 < len(recovered) < len(fixture.stream_payload)


def _verify_xz_prefix(result: RepairResult, fixture: MatrixFixture) -> None:
    recovered = lzma.decompress(Path(result.repaired_input["path"]).read_bytes())
    assert fixture.stream_payload is not None
    assert fixture.stream_payload.startswith(recovered)
    assert 0 < len(recovered) < len(fixture.stream_payload)


def _verify_zstd_prefix(result: RepairResult, fixture: MatrixFixture) -> None:
    zstd = pytest.importorskip("zstandard")
    recovered = _zstd_decompress_all(zstd, Path(result.repaired_input["path"]).read_bytes())
    assert fixture.stream_payload is not None
    assert fixture.stream_payload.startswith(recovered)
    assert 0 < len(recovered) < len(fixture.stream_payload)


def _verify_tar_zstd(result: RepairResult, fixture: MatrixFixture) -> None:
    zstd = pytest.importorskip("zstandard")
    decoded = _zstd_decompress_all(zstd, Path(result.repaired_input["path"]).read_bytes())
    with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
        assert sorted(item.name for item in archive.getmembers() if item.isfile()) == sorted(fixture.tar_entries)
        for name, payload in fixture.tar_entries.items():
            member = archive.extractfile(name)
            assert member is not None
            assert member.read() == payload


def _zstd_decompress_all(zstd, data: bytes) -> bytes:
    with zstd.ZstdDecompressor().stream_reader(io.BytesIO(data)) as reader:
        return reader.read()


def _pseudo_random_payload(size: int) -> bytes:
    value = 0x12345678
    output = bytearray()
    for _ in range(size):
        value ^= (value << 13) & 0xFFFFFFFF
        value ^= value >> 17
        value ^= (value << 5) & 0xFFFFFFFF
        output.append(value & 0xFF)
    return bytes(output)


def _zip_entries() -> dict[str, bytes]:
    return {
        "alpha.txt": b"alpha payload",
        "bravo.bin": b"bravo payload",
    }


def _zip_bytes(entries: dict[str, bytes] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in (entries or _zip_entries()).items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def _zip_eocd_offset(data: bytes) -> int:
    offset = data.rfind(b"PK\x05\x06")
    assert offset >= 0
    return offset


def _zip_cd_offset(data: bytes) -> int:
    return struct.unpack_from("<I", data, _zip_eocd_offset(data) + 16)[0]


def _zip_payload_offset(data: bytes, name: str) -> int:
    encoded = name.encode("utf-8")
    offset = data.find(b"PK\x03\x04")
    while offset >= 0:
        name_len, extra_len = struct.unpack_from("<HH", data, offset + 26)
        start = offset + 30
        if data[start:start + name_len] == encoded:
            return start + name_len + extra_len
        offset = data.find(b"PK\x03\x04", offset + 4)
    raise AssertionError(f"ZIP entry not found: {name}")


def _build_zip_trailing_junk(root: Path) -> MatrixFixture:
    original = _zip_bytes()
    return _fixture_from_bytes(root, "zip-tail.zip", original + b"JUNK", expected_bytes=original, zip_entries=_zip_entries())


def _build_zip_bad_comment_length(root: Path) -> MatrixFixture:
    data = bytearray(_zip_bytes())
    struct.pack_into("<H", data, _zip_eocd_offset(data) + 20, 14)
    return _fixture_from_bytes(root, "zip-comment-len.zip", bytes(data), zip_entries=_zip_entries())


def _build_zip_bad_cd_offset(root: Path) -> MatrixFixture:
    data = bytearray(_zip_bytes())
    struct.pack_into("<I", data, _zip_eocd_offset(data) + 16, 0)
    return _fixture_from_bytes(root, "zip-cd-offset.zip", bytes(data), zip_entries=_zip_entries())


def _build_zip_bad_cd_count(root: Path) -> MatrixFixture:
    data = bytearray(_zip_bytes())
    struct.pack_into("<HH", data, _zip_eocd_offset(data) + 8, 1, 1)
    return _fixture_from_bytes(root, "zip-cd-count.zip", bytes(data), zip_entries=_zip_entries())


def _build_zip_missing_eocd(root: Path) -> MatrixFixture:
    data = _zip_bytes()
    return _fixture_from_bytes(root, "zip-missing-eocd.zip", data[:_zip_eocd_offset(data)], zip_entries=_zip_entries())


def _build_zip_missing_cd(root: Path) -> MatrixFixture:
    data = _zip_bytes()
    return _fixture_from_bytes(root, "zip-missing-cd.zip", data[:_zip_cd_offset(data)], zip_entries=_zip_entries())


def _build_zip_local_name_len_bad(root: Path) -> MatrixFixture:
    original = _zip_bytes({"local-name.txt": b"payload"})
    data = bytearray(original)
    struct.pack_into("<H", data, 26, len("local-name.txt") - 1)
    return _fixture_from_bytes(root, "zip-local-name-len-bad.zip", bytes(data), expected_bytes=original, zip_entries={"local-name.txt": b"payload"})


def _build_zip_local_size_crc_bad(root: Path) -> MatrixFixture:
    original = _zip_bytes({"local-size.txt": b"size payload"})
    data = bytearray(original)
    struct.pack_into("<III", data, 14, 0, 0, 0)
    return _fixture_from_bytes(root, "zip-local-size-crc-bad.zip", bytes(data), expected_bytes=original, zip_entries={"local-size.txt": b"size payload"})


def _build_zip_local_bit3_flag_bad(root: Path) -> MatrixFixture:
    original = _descriptor_zip_with_central("bit3.txt", b"bit3 payload")
    data = bytearray(original)
    struct.pack_into("<H", data, 6, 0)
    return _fixture_from_bytes(root, "zip-local-bit3-bad.zip", bytes(data), expected_bytes=original, zip_entries={"bit3.txt": b"bit3 payload"})


def _build_zip_descriptor(root: Path) -> MatrixFixture:
    payload = b"descriptor payload"
    return _fixture_from_bytes(
        root,
        "zip-descriptor.zip",
        _descriptor_zip_fragment("descriptor.txt", payload),
        zip_entries={"descriptor.txt": payload},
    )


def _build_zip64_descriptor(root: Path) -> MatrixFixture:
    payload = b"zip64 descriptor payload"
    return _fixture_from_bytes(
        root,
        "zip64-descriptor.zip",
        _descriptor_zip_fragment("zip64.txt", payload, zip64=True),
        zip_entries={"zip64.txt": payload},
    )


def _build_zip64_missing_locator(root: Path) -> MatrixFixture:
    original = _zip64_bytes()
    locator_offset = original.find(b"PK\x06\x07")
    eocd = _zip_eocd_offset(original)
    assert locator_offset >= 0
    damaged = original[:locator_offset] + original[eocd:]
    return _fixture_from_bytes(root, "zip64-missing-locator.zip", damaged, expected_bytes=original, zip_entries={"zip64.txt": b"zip64 payload"})


def _build_zip64_bad_record_fields(root: Path) -> MatrixFixture:
    original = _zip64_bytes()
    data = bytearray(original)
    zip64_offset = original.find(b"PK\x06\x06")
    assert zip64_offset >= 0
    struct.pack_into("<QQQ", data, zip64_offset + 24, 2, 2, 1)
    struct.pack_into("<Q", data, zip64_offset + 48, 0)
    return _fixture_from_bytes(root, "zip64-bad-record-fields.zip", bytes(data), expected_bytes=original, zip_entries={"zip64.txt": b"zip64 payload"})


def _build_zip64_bad_central_extra(root: Path) -> MatrixFixture:
    original = _zip64_bytes()
    data = bytearray(original)
    cd = data.find(b"PK\x01\x02")
    name_len, _extra_len = struct.unpack_from("<HH", data, cd + 28)
    extra_offset = cd + 46 + name_len
    assert data[extra_offset:extra_offset + 4] == b"\x01\0\x18\0"
    struct.pack_into("<Q", data, extra_offset + 4, 1)
    struct.pack_into("<Q", data, extra_offset + 20, 99)
    return _fixture_from_bytes(root, "zip64-bad-central-extra.zip", bytes(data), expected_bytes=original, zip_entries={"zip64.txt": b"zip64 payload"})


def _build_zip_multiple_directory_fields(root: Path) -> MatrixFixture:
    data = bytearray(_zip_bytes())
    eocd = _zip_eocd_offset(data)
    struct.pack_into("<HH", data, eocd + 8, 1, 1)
    struct.pack_into("<I", data, eocd + 16, 0)
    return _fixture_from_bytes(root, "zip-multi-cd.zip", bytes(data), zip_entries=_zip_entries())


def _build_zip_eocd_four_field_combo(root: Path) -> MatrixFixture:
    original = _zip_bytes()
    data = bytearray(original)
    eocd = _zip_eocd_offset(data)
    struct.pack_into("<HH", data, eocd + 8, 1, 1)
    struct.pack_into("<I", data, eocd + 16, 0)
    struct.pack_into("<H", data, eocd + 20, 0)
    return _fixture_from_bytes(
        root,
        "zip-eocd-four-field-combo.zip",
        bytes(data) + b"JUNK",
        expected_bytes=original,
        zip_entries=_zip_entries(),
    )


def _build_zip_split_trailing_junk(root: Path) -> MatrixFixture:
    original = _zip_bytes()
    return _fixture_from_ranges(
        root,
        "zip-split-tail.zip",
        original + b"SPLIT-JUNK",
        split_at=41,
        expected_bytes=original,
        zip_entries=_zip_entries(),
    )


def _build_zip_missing_split_volume_with_extra_damage(root: Path) -> MatrixFixture:
    original = _zip_bytes()
    return _fixture_from_bytes(root, "zip-missing-volume-extra-damage.zip.001", original[:57] + b"JUNK")


def _build_zip_sfx_prefix_tail(root: Path) -> MatrixFixture:
    original = _zip_bytes()
    prefix = b"MZ\x90\x00SUNPACK-SFX-STUB"
    return _fixture_from_bytes(root, "zip-sfx.exe", prefix + original + b"TAIL", expected_bytes=original, zip_entries=_zip_entries())


def _build_zip_sfx_split_prefix_tail(root: Path) -> MatrixFixture:
    original = _zip_bytes()
    prefix = b"MZ\x90\x00SFX-SPLIT"
    return _fixture_from_ranges(
        root,
        "zip-sfx-split.exe",
        prefix + original + b"TAIL",
        split_at=len(prefix) + 53,
        expected_bytes=original,
        zip_entries=_zip_entries(),
    )


def _build_zip_sfx_split_prefix_tail_bad_cd(root: Path) -> MatrixFixture:
    data = bytearray(_zip_bytes())
    eocd = _zip_eocd_offset(data)
    struct.pack_into("<HH", data, eocd + 8, 1, 1)
    struct.pack_into("<I", data, eocd + 16, 0)
    prefix = b"MZ\x90\x00SFX-SPLIT-BAD-CD"
    payload = prefix + bytes(data) + b"TAIL"
    return _fixture_from_ranges(
        root,
        "zip-sfx-split-bad-cd.exe",
        payload,
        split_at=len(prefix) + 47,
        zip_entries=_zip_entries(),
    )


def _build_zip_fake_local_header_before_real_sfx(root: Path) -> MatrixFixture:
    original = _zip_bytes()
    fake_header = b"PK\x03\x04" + b"\x14\x00" + b"FAKE-LOCAL-HEADER-NO-PAYLOAD"
    prefix = b"MZ\x90\x00SFX-STUB" + fake_header + (b"\0" * 17)
    return _fixture_from_bytes(
        root,
        "zip-fake-local-before-real-sfx.exe",
        prefix + original + b"TAIL",
        expected_bytes=original,
        zip_entries=_zip_entries(),
    )


def _build_zip_single_payload_crc_bad(root: Path) -> MatrixFixture:
    entries = {"only.txt": b"one payload"}
    data = bytearray(_zip_bytes(entries))
    data[_zip_payload_offset(data, "only.txt")] ^= 0x55
    return _fixture_from_bytes(root, "zip-single-payload-bad.zip", bytes(data))


def _build_zip_one_bad_payload_one_good(root: Path) -> MatrixFixture:
    entries = {"bad.txt": b"bad payload", "good.txt": b"good payload"}
    data = bytearray(_zip_bytes(entries))
    data[_zip_payload_offset(data, "bad.txt")] ^= 0x55
    return _fixture_from_bytes(root, "zip-one-bad-payload.zip", bytes(data), zip_entries={"good.txt": b"good payload"})


def _build_zip_partial_recovery_damaged_local_header(root: Path) -> MatrixFixture:
    entries = {"bad.txt": b"broken", "good.txt": b"still here"}
    data = bytearray(_zip_bytes(entries))
    first_lfh = data.find(b"PK\x03\x04")
    data[first_lfh:first_lfh + 4] = b"BAD!"
    return _fixture_from_bytes(root, "zip-partial-local-header.zip", bytes(data), zip_entries={"good.txt": b"still here"})


def _build_zip_entry_quarantine_two_bad_two_good(root: Path) -> MatrixFixture:
    entries = {
        "bad-1.txt": b"bad payload one" * 20,
        "good-1.txt": b"good payload one" * 20,
        "bad-2.txt": b"bad payload two" * 20,
        "good-2.txt": b"good payload two" * 20,
    }
    data = bytearray(_zip_bytes(entries))
    data[_zip_payload_offset(data, "bad-1.txt") + 2] ^= 0x55
    data[_zip_payload_offset(data, "bad-2.txt") + 3] ^= 0x55
    return _fixture_from_bytes(
        root,
        "zip-quarantine-two-bad.zip",
        bytes(data),
        zip_entries={
            "good-1.txt": entries["good-1.txt"],
            "good-2.txt": entries["good-2.txt"],
        },
    )


def _build_zip_missing_cd_multiple_local_headers_one_bad_payload(root: Path) -> MatrixFixture:
    entries = {
        "bad.txt": b"bad payload",
        "good-1.txt": b"good payload one",
        "good-2.txt": b"good payload two",
    }
    data = bytearray(_zip_bytes(entries))
    data[_zip_payload_offset(data, "bad.txt")] ^= 0x55
    payload = bytes(data[:_zip_cd_offset(data)])
    return _fixture_from_bytes(
        root,
        "zip-missing-cd-multi-one-bad.zip",
        payload,
        zip_entries={
            "good-1.txt": b"good payload one",
            "good-2.txt": b"good payload two",
        },
    )


def _build_zip_descriptor_payload_bad_keeps_other_descriptor_entry(root: Path) -> MatrixFixture:
    bad_payload = b"bad descriptor payload"
    corrupted = bytearray(bad_payload)
    corrupted[3] ^= 0x55
    good_payload = b"good descriptor payload"
    data = b"".join([
        _descriptor_zip_entry_fragment("bad-dd.txt", bad_payload, stored_payload=bytes(corrupted)),
        _descriptor_zip_entry_fragment("good-dd.txt", good_payload),
        b"PK\x01\x02BROKEN-CENTRAL-DIR",
    ])
    return _fixture_from_bytes(
        root,
        "zip-descriptor-one-payload-bad.zip",
        data,
        zip_entries={"good-dd.txt": good_payload},
    )


def _build_zip64_descriptor_payload_bad_keeps_other_descriptor_entry(root: Path) -> MatrixFixture:
    bad_payload = b"bad zip64 descriptor payload"
    corrupted = bytearray(bad_payload)
    corrupted[5] ^= 0x55
    good_payload = b"good zip64 descriptor payload"
    data = b"".join([
        _descriptor_zip_entry_fragment("bad-zip64-dd.txt", bad_payload, zip64=True, stored_payload=bytes(corrupted)),
        _descriptor_zip_entry_fragment("good-zip64-dd.txt", good_payload, zip64=True),
        b"PK\x01\x02BROKEN-CENTRAL-DIR",
    ])
    return _fixture_from_bytes(
        root,
        "zip64-descriptor-one-payload-bad.zip",
        data,
        zip_entries={"good-zip64-dd.txt": good_payload},
    )


def _build_zip_multi_structure_and_payload_bad(root: Path) -> MatrixFixture:
    entries = {"bad.txt": b"bad payload", "good.txt": b"good payload"}
    data = bytearray(_zip_bytes(entries))
    data[_zip_payload_offset(data, "bad.txt")] ^= 0x55
    eocd = _zip_eocd_offset(data)
    struct.pack_into("<HH", data, eocd + 8, 1, 1)
    struct.pack_into("<I", data, eocd + 16, 0)
    struct.pack_into("<H", data, eocd + 20, 0)
    return _fixture_from_bytes(
        root,
        "zip-multi-structure-payload-bad.zip",
        bytes(data) + b"JUNK",
        zip_entries={"good.txt": b"good payload"},
    )


def _build_zip_eocd_then_entry_quarantine(root: Path) -> MatrixFixture:
    entries = {"bad.txt": b"bad payload", "good.txt": b"good payload"}
    data = bytearray(_zip_bytes(entries))
    data[_zip_payload_offset(data, "bad.txt")] ^= 0x55
    eocd = _zip_eocd_offset(data)
    struct.pack_into("<HH", data, eocd + 8, 1, 1)
    struct.pack_into("<I", data, eocd + 16, 0)
    struct.pack_into("<H", data, eocd + 20, 8)
    return _fixture_from_bytes(
        root,
        "zip-eocd-then-quarantine.zip",
        bytes(data) + b"TAILJUNK",
        zip_entries={"good.txt": b"good payload"},
    )


def _build_zip_duplicate_conflict(root: Path) -> MatrixFixture:
    good_payload = b"good duplicate payload"
    data = b"".join([
        _raw_stored_local_entry("dup.txt", b"bad payload", crc32=0),
        _raw_stored_local_entry("dup.txt", good_payload),
        b"PK\x01\x02BROKEN-CENTRAL-DIR",
    ])
    return _fixture_from_bytes(root, "zip-duplicate-conflict.zip", data, zip_entries={"dup.txt": good_payload})


def _build_nested_zip_payload(root: Path) -> MatrixFixture:
    entries = {"inner.txt": b"nested payload"}
    inner_zip = _zip_bytes(entries)
    return _fixture_from_bytes(root, "zip-nested-in-damaged-container.bin", b"outer-broken" + inner_zip + b"outer-tail", zip_entries=entries)


def _build_nested_zip_then_entry_quarantine(root: Path) -> MatrixFixture:
    entries = {"bad.txt": b"bad payload", "good.txt": b"nested good payload"}
    data = bytearray(_zip_bytes(entries))
    data[_zip_payload_offset(data, "bad.txt")] ^= 0x55
    return _fixture_from_bytes(
        root,
        "nested-zip-then-quarantine.bin",
        b"outer-damaged-prefix" + bytes(data) + b"outer-damaged-tail",
        zip_entries={"good.txt": b"nested good payload"},
    )


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


def _descriptor_zip_entry_fragment(name: str, payload: bytes, *, zip64: bool = False, stored_payload: bytes | None = None) -> bytes:
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
            45 if zip64 else 20,
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
        stored_payload if stored_payload is not None else payload,
        descriptor,
    ])


def _descriptor_zip_fragment(name: str, payload: bytes, *, zip64: bool = False) -> bytes:
    return b"".join([
        _descriptor_zip_entry_fragment(name, payload, zip64=zip64),
        b"PK\x01\x02BROKEN-CENTRAL-DIR",
    ])


def _descriptor_zip_with_central(name: str, payload: bytes) -> bytes:
    encoded = name.encode("utf-8")
    crc32 = zlib.crc32(payload) & 0xFFFFFFFF
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0x08,
        0,
        0,
        0,
        0,
        0,
        0,
        len(encoded),
        0,
    ) + encoded + payload + struct.pack("<IIII", 0x08074B50, crc32, len(payload), len(payload))
    cd_offset = len(local)
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        0x08,
        0,
        0,
        0,
        crc32,
        len(payload),
        len(payload),
        len(encoded),
        0,
        0,
        0,
        0,
        0,
        0,
    ) + encoded
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), cd_offset, 0)
    return local + central + eocd


def _zip64_bytes() -> bytes:
    name = b"zip64.txt"
    payload = b"zip64 payload"
    crc32 = zlib.crc32(payload) & 0xFFFFFFFF
    local_extra = struct.pack("<HHQQ", 0x0001, 16, len(payload), len(payload))
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        45,
        0,
        0,
        0,
        0,
        crc32,
        0xFFFFFFFF,
        0xFFFFFFFF,
        len(name),
        len(local_extra),
    ) + name + local_extra + payload
    cd_offset = len(local)
    central_extra = struct.pack("<HHQQQ", 0x0001, 24, len(payload), len(payload), 0)
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        45,
        45,
        0,
        0,
        0,
        0,
        crc32,
        0xFFFFFFFF,
        0xFFFFFFFF,
        len(name),
        len(central_extra),
        0,
        0,
        0,
        0,
        0xFFFFFFFF,
    ) + name + central_extra
    zip64_offset = cd_offset + len(central)
    zip64_eocd = struct.pack("<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, 1, 1, len(central), cd_offset)
    locator = struct.pack("<IIQI", 0x07064B50, 0, zip64_offset, 1)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return local + central + zip64_eocd + locator + eocd


def _seven_zip_bytes(*, minor: int = 4, gap: bytes = b"abcde", next_header: bytes = b"\x01") -> bytes:
    start_header = struct.pack("<QQI", len(gap), len(next_header), zlib.crc32(next_header) & 0xFFFFFFFF)
    return (
        b"7z\xbc\xaf\x27\x1c"
        + bytes([0, minor])
        + struct.pack("<I", zlib.crc32(start_header) & 0xFFFFFFFF)
        + start_header
        + gap
        + next_header
    )


def _patch_7z_next_crc(data: bytes, value: int, *, recompute_start_crc: bool) -> bytes:
    output = bytearray(data)
    struct.pack_into("<I", output, 28, value)
    if recompute_start_crc:
        struct.pack_into("<I", output, 8, zlib.crc32(output[12:32]) & 0xFFFFFFFF)
    return bytes(output)


def _build_7z_trailing_junk_v04(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes(minor=4)
    return _fixture_from_bytes(root, "seven-tail.7z", original + b"JUNK", expected_bytes=original)


def _build_7z_start_crc_bad_v03(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes(minor=3)
    data = bytearray(original)
    data[8:12] = b"\0\0\0\0"
    return _fixture_from_bytes(root, "seven-start-crc.7z", bytes(data), expected_bytes=original)


def _build_7z_next_crc_bad(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes(minor=4)
    data = _patch_7z_next_crc(original, 0, recompute_start_crc=True)
    return _fixture_from_bytes(root, "seven-next-crc.7z", data, expected_bytes=original)


def _build_7z_next_header_offset_bad(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes(gap=b"abcdefgh", next_header=b"\x01\x02\x03")
    data = bytearray(original)
    struct.pack_into("<Q", data, 12, 0)
    struct.pack_into("<I", data, 8, zlib.crc32(data[12:32]) & 0xFFFFFFFF)
    return _fixture_from_bytes(root, "seven-next-offset-bad.7z", bytes(data), expected_bytes=original)


def _build_7z_next_header_size_bad(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes(gap=b"abcdefgh", next_header=b"\x17\x02\x03\x04")
    data = bytearray(original)
    struct.pack_into("<Q", data, 20, 1)
    struct.pack_into("<I", data, 8, zlib.crc32(data[12:32]) & 0xFFFFFFFF)
    return _fixture_from_bytes(root, "seven-next-size-bad.7z", bytes(data), expected_bytes=original)


def _build_7z_start_and_next_crc_bad(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes(minor=4)
    data = _patch_7z_next_crc(original, 0, recompute_start_crc=False)
    data = data[:8] + b"\0\0\0\0" + data[12:]
    return _fixture_from_bytes(root, "seven-two-crc.7z", data, expected_bytes=original)


def _build_7z_crc_fields_and_trailing_junk(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes(minor=4)
    data = _patch_7z_next_crc(original, 0, recompute_start_crc=False)
    data = data[:8] + b"\0\0\0\0" + data[12:] + b"JUNK"
    return _fixture_from_bytes(root, "seven-crc-fields-tail.7z", data, expected_bytes=original)


def _build_7z_v03_start_next_crc_and_trailing_junk(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes(minor=3, next_header=b"\x01\x02")
    data = _patch_7z_next_crc(original, 0, recompute_start_crc=False)
    data = data[:8] + b"\0\0\0\0" + data[12:] + b"JUNK"
    return _fixture_from_bytes(root, "seven-v03-crc-fields-tail.7z", data, expected_bytes=original)


def _build_7z_sfx_prefix_tail(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes()
    return _fixture_from_bytes(root, "seven-sfx.exe", b"MZ-STUB" + original + b"TAIL", expected_bytes=original)


def _build_7z_sfx_fake_magic_then_real_payload(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes()
    fake = b"7z\xbc\xaf\x27\x1c" + b"\xff\xff" + b"NOT-A-VALID-7Z-HEADER"
    prefix = b"MZ-FAKE-7Z-SFX" + fake + b"\0" * 11
    return _fixture_from_bytes(root, "seven-sfx-fake-magic.exe", prefix + original + b"TAIL", expected_bytes=original)


def _build_7z_split_trailing_junk(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes()
    return _fixture_from_ranges(root, "seven-split.7z", original + b"JUNK", split_at=19, expected_bytes=original)


def _build_7z_sfx_split_prefix_tail(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes()
    prefix = b"MZ-SFX-SPLIT"
    return _fixture_from_ranges(root, "seven-sfx-split.exe", prefix + original + b"TAIL", split_at=len(prefix) + 13, expected_bytes=original)


def _build_archive_carrier_crop_embedded_7z(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes()
    return _fixture_from_bytes(root, "archive-carrier-crop.bin", b"JPEGDATA" + original, expected_bytes=original)


def _build_7z_payload_bad(root: Path) -> MatrixFixture:
    data = bytearray(_seven_zip_bytes(next_header=b"\x01\x02"))
    data[-1] ^= 0x55
    return _fixture_from_bytes(root, "seven-payload-bad.7z", bytes(data))


def _build_7z_missing_split_volume(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes(gap=b"abcdefghij", next_header=b"\x01\x02\x03")
    return _fixture_from_bytes(root, "seven-missing-volume.7z.001", original[:26])


def _build_7z_missing_middle_volume_plus_crc_noise(root: Path) -> MatrixFixture:
    original = _seven_zip_bytes(gap=b"abcdefghij", next_header=b"\x01\x02\x03")
    noisy = _patch_7z_next_crc(original, 0, recompute_start_crc=False)
    noisy = noisy[:8] + b"\0\0\0\0" + noisy[12:]
    return _fixture_from_bytes(root, "seven-missing-middle-crc-noise.7z.001", noisy[:28] + b"CRC-NOISE")


def _build_7z_solid_block_salvage(root: Path) -> MatrixFixture:
    seven_zip = _require_7z_tool()
    root.mkdir(parents=True, exist_ok=True)
    source_dir = root / "seven-src"
    source_dir.mkdir()
    entries = {
        "alpha.txt": b"alpha 7z payload",
        "bravo.txt": b"bravo 7z payload",
    }
    for name, payload in entries.items():
        (source_dir / name).write_bytes(payload)
    source = root / "seven-solid.7z"
    subprocess.run(
        [str(seven_zip), "a", "-t7z", "-ms=on", str(source.resolve()), "alpha.txt", "bravo.txt"],
        cwd=str(source_dir),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return MatrixFixture(source_input={"kind": "file", "path": str(source)}, zip_entries=entries)


def _build_7z_crc_then_solid_salvage(root: Path) -> MatrixFixture:
    fixture = _build_7z_solid_block_salvage(root)
    path = Path(fixture.source_input["path"])
    data = bytearray(path.read_bytes())
    data[8:12] = b"\0\0\0\0"
    path.write_bytes(bytes(data))
    return fixture


def _require_7z_tool() -> Path:
    candidate = Path("tools") / "7z.exe"
    if candidate.is_file():
        return candidate.resolve()
    found = shutil.which("7z")
    if found:
        return Path(found)
    pytest.skip("7z executable is required for 7z solid salvage fixture")


def _build_zstd_frame_salvage(root: Path) -> MatrixFixture:
    zstd = pytest.importorskip("zstandard")
    first = zstd.ZstdCompressor(level=0).compress(b"bad frame payload" * 8)
    second_payload = b"good frame one" * 8
    third_payload = b"good frame two" * 8
    second = zstd.ZstdCompressor(level=0).compress(second_payload)
    third = zstd.ZstdCompressor(level=0).compress(third_payload)
    damaged = bytearray(first)
    damaged[4:12] = b"\xff" * 8
    return _fixture_from_bytes(
        root,
        "zstd-frame-salvage.zst",
        bytes(damaged) + second + third,
        stream_payload=second_payload + third_payload,
    )


def _build_gzip_deflate_member_resync(root: Path) -> MatrixFixture:
    first = bytearray(gzip.compress(b"bad gzip member" * 16))
    first[len(first) // 2] ^= 0x55
    second_payload = b"good gzip member one" * 8
    third_payload = b"good gzip member two" * 8
    data = bytes(first) + gzip.compress(second_payload) + gzip.compress(third_payload)
    return _fixture_from_bytes(root, "gzip-member-resync.gz", data, stream_payload=second_payload + third_payload)


RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"


def _rar4_block(header_type: int, flags: int = 0, payload: bytes = b"") -> bytes:
    add_size = len(payload).to_bytes(4, "little") if payload else b""
    header_size = 7 + len(add_size)
    body = bytes([header_type]) + flags.to_bytes(2, "little") + header_size.to_bytes(2, "little") + add_size
    header_crc = (zlib.crc32(body) & 0xFFFF).to_bytes(2, "little")
    return header_crc + body + payload


def _rar4_bytes(*, file_payload: bytes = b"") -> bytes:
    file_block = _rar4_block(0x74, flags=0x8000, payload=file_payload) if file_payload else b""
    return RAR4_MAGIC + _rar4_block(0x73) + file_block + _rar4_block(0x7B)


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


def _rar5_main_block(archive_flags: int = 0) -> bytes:
    fields = _rar5_vint(1) + _rar5_vint(0) + _rar5_vint(archive_flags)
    header_data = _rar5_vint(len(fields)) + fields
    return zlib.crc32(header_data).to_bytes(4, "little") + header_data


def _rar5_bytes(*, file_payload: bytes = b"") -> bytes:
    file_block = _rar5_block(2, data=file_payload) if file_payload else b""
    return RAR5_MAGIC + _rar5_block(1) + file_block + _rar5_block(5)


def _build_rar4_trailing_junk(root: Path) -> MatrixFixture:
    original = _rar4_bytes()
    return _fixture_from_bytes(root, "rar4-tail.rar", original + b"JUNK", expected_bytes=original)


def _build_rar5_trailing_junk(root: Path) -> MatrixFixture:
    original = _rar5_bytes()
    return _fixture_from_bytes(root, "rar5-tail.rar", original + b"JUNK", expected_bytes=original)


def _build_rar4_missing_end(root: Path) -> MatrixFixture:
    original_without_end = RAR4_MAGIC + _rar4_block(0x73) + _rar4_block(0x74, flags=0x8000, payload=b"payload")
    expected = original_without_end + _rar4_block(0x7B)
    return _fixture_from_bytes(root, "rar4-missing-end.rar", original_without_end, expected_bytes=expected)


def _build_rar5_missing_end(root: Path) -> MatrixFixture:
    original_without_end = RAR5_MAGIC + _rar5_block(1) + _rar5_block(2, data=b"payload")
    expected = original_without_end + _rar5_block(5)
    return _fixture_from_bytes(root, "rar5-missing-end.rar", original_without_end, expected_bytes=expected)


def _build_rar5_missing_end_with_trailing_junk(root: Path) -> MatrixFixture:
    original_without_end = RAR5_MAGIC + _rar5_block(1) + _rar5_block(2, data=b"payload")
    expected = original_without_end + _rar5_block(5)
    return _fixture_from_bytes(root, "rar5-missing-end-tail.rar", original_without_end + b"TAIL", expected_bytes=expected)


def _build_rar4_sfx_prefix_tail(root: Path) -> MatrixFixture:
    original = _rar4_bytes()
    return _fixture_from_bytes(root, "rar4-sfx.exe", b"MZ-STUB" + original + b"TAIL", expected_bytes=original)


def _build_rar5_sfx_split_prefix_tail(root: Path) -> MatrixFixture:
    original = _rar5_bytes()
    prefix = b"MZ-SFX-SPLIT"
    return _fixture_from_ranges(root, "rar5-sfx-split.exe", prefix + original + b"TAIL", split_at=len(prefix) + 9, expected_bytes=original)


def _build_rar5_sfx_split_tail_missing_end(root: Path) -> MatrixFixture:
    original_without_end = RAR5_MAGIC + _rar5_block(1) + _rar5_block(2, data=b"payload")
    expected = original_without_end + _rar5_block(5)
    prefix = b"MZ-SFX-SPLIT"
    return _fixture_from_ranges(
        root,
        "rar5-sfx-split-missing-end.exe",
        prefix + original_without_end + b"TAIL",
        split_at=len(prefix) + 11,
        expected_bytes=expected,
    )


def _build_rar5_fake_magic_sfx_then_real_missing_end(root: Path) -> MatrixFixture:
    original_without_end = RAR5_MAGIC + _rar5_block(1) + _rar5_block(2, data=b"payload")
    expected = original_without_end + _rar5_block(5)
    fake = RAR5_MAGIC + b"NOT-A-VALID-RAR5-BLOCK"
    prefix = b"MZ-FAKE-RAR5-SFX" + fake + b"\0" * 9
    return _fixture_from_bytes(
        root,
        "rar5-fake-magic-sfx-missing-end.exe",
        prefix + original_without_end + b"TAIL",
        expected_bytes=expected,
    )


def _build_rar4_split_trailing_junk(root: Path) -> MatrixFixture:
    original = _rar4_bytes()
    return _fixture_from_ranges(root, "rar4-split.rar", original + b"JUNK", split_at=12, expected_bytes=original)


def _build_rar4_block_chain_trim(root: Path) -> MatrixFixture:
    original = _rar4_bytes()
    return _fixture_from_bytes(root, "rar4-block-chain-tail.rar", b"SFX" + original + b"JUNK", expected_bytes=original)


def _build_rar4_payload_bad(root: Path) -> MatrixFixture:
    data = bytearray(_rar4_bytes(file_payload=b"payload"))
    payload_offset = data.index(b"payload")
    data[payload_offset] ^= 0x55
    return _fixture_from_bytes(root, "rar4-payload-bad.rar", bytes(data))


def _build_rar5_missing_split_volume(root: Path) -> MatrixFixture:
    data = RAR5_MAGIC + _rar5_block(1) + _rar5_block(2, data=b"payload")
    return _fixture_from_bytes(root, "rar5-missing-volume.part1.rar", data)


def _build_rar5_file_quarantine(root: Path) -> MatrixFixture:
    payload = b"rar payload"
    complete_prefix = RAR5_MAGIC + _rar5_block(1) + _rar5_block(2, data=payload)
    expected = RAR5_MAGIC + _rar5_main_block() + _rar5_block(2, data=payload) + _rar5_block(5)
    return _fixture_from_bytes(
        root,
        "rar5-file-quarantine.rar",
        complete_prefix + b"BROKEN-RAR5-BLOCK",
        expected_bytes=expected,
    )


def _build_rar5_carrier_then_file_quarantine(root: Path) -> MatrixFixture:
    payload = b"rar payload"
    complete_prefix = RAR5_MAGIC + _rar5_block(1) + _rar5_block(2, data=payload)
    expected = RAR5_MAGIC + _rar5_main_block() + _rar5_block(2, data=payload) + _rar5_block(5)
    return _fixture_from_bytes(
        root,
        "rar5-carrier-then-quarantine.exe",
        b"MZ-SFX-PREFIX" + complete_prefix + b"BROKEN-RAR5-BLOCK" + b"TAIL",
        expected_bytes=expected,
    )


def _tar_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _tar_entries() -> dict[str, bytes]:
    return {"payload.txt": b"tar payload"}


def _build_tar_bad_checksum(root: Path) -> MatrixFixture:
    data = bytearray(_tar_bytes(_tar_entries()))
    data[148:156] = b"000000\0 "
    return _fixture_from_bytes(root, "tar-bad-checksum.tar", bytes(data), tar_entries=_tar_entries())


def _build_tar_checksum_and_missing_zero_blocks(root: Path) -> MatrixFixture:
    data = bytearray(_tar_bytes(_tar_entries())[:1024])
    data[148:156] = b"000000\0 "
    return _fixture_from_bytes(root, "tar-checksum-missing-zero.tar", bytes(data), tar_entries=_tar_entries())


def _build_tar_checksum_and_trailing_junk(root: Path) -> MatrixFixture:
    data = bytearray(_tar_bytes(_tar_entries()) + b"JUNK")
    data[148:156] = b"000000\0 "
    return _fixture_from_bytes(root, "tar-checksum-tail.tar", bytes(data), tar_entries=_tar_entries())


def _build_tar_missing_zero_blocks(root: Path) -> MatrixFixture:
    data = _tar_bytes(_tar_entries())
    return _fixture_from_bytes(root, "tar-missing-zero.tar", data[:1024], tar_entries=_tar_entries())


def _build_tar_trailing_junk(root: Path) -> MatrixFixture:
    data = _tar_bytes(_tar_entries())
    return _fixture_from_bytes(root, "tar-tail.tar", data + b"JUNK", tar_entries=_tar_entries())


def _build_tar_payload_truncated(root: Path) -> MatrixFixture:
    data = _tar_bytes({"payload.bin": b"x" * 2048})
    return _fixture_from_bytes(root, "tar-payload-truncated.tar", data[:700])


def _build_tar_metadata_downgrade(root: Path) -> MatrixFixture:
    payload = b"tar metadata downgrade payload"
    pax_payload = b"25 path=ignored-long-name.txt\n"
    data = b"".join([
        _tar_raw_header("./PaxHeaders.0/payload.txt", len(pax_payload), b"x"),
        pax_payload + (b"\0" * ((512 - len(pax_payload) % 512) % 512)),
        _tar_raw_header("payload.txt", len(payload), b"0"),
        payload + (b"\0" * ((512 - len(payload) % 512) % 512)),
        b"\0" * 1024,
    ])
    return _fixture_from_bytes(root, "tar-metadata-downgrade.tar", data, tar_entries={"payload.txt": payload})


def _build_tar_sparse_pax_longname(root: Path) -> MatrixFixture:
    long_name = "very/" + "deep/" * 18 + "payload.txt"
    payload = b"tar payload after longname"
    data = b"".join([
        _tar_raw_header("././@LongLink", len(long_name) + 1, b"L"),
        (long_name.encode("utf-8") + b"\0").ljust(512, b"\0"),
        _tar_raw_header("short.txt", len(payload), b"0"),
        payload.ljust(512, b"\0"),
        b"\0" * 1024,
    ])
    return _fixture_from_bytes(root, "tar-sparse-pax-longname.tar", data, tar_entries={long_name: payload})


def _build_tar_sparse_then_trailing_zero(root: Path) -> MatrixFixture:
    long_name = "very/" + "deep/" * 18 + "payload.txt"
    payload = b"tar payload before missing zero blocks"
    data = b"".join([
        _tar_raw_header("././@LongLink", len(long_name) + 1, b"L"),
        (long_name.encode("utf-8") + b"\0").ljust(512, b"\0"),
        _tar_raw_header("short.txt", len(payload), b"0"),
        payload.ljust(512, b"\0"),
    ])
    return _fixture_from_bytes(root, "tar-sparse-then-zero.tar", data, tar_entries={long_name: payload})


def _build_tar_gzip_truncated_keeps_complete_member(root: Path) -> MatrixFixture:
    entries = {
        "complete.txt": b"complete payload",
        "truncated.bin": bytes(range(256)) * 8,
    }
    tar_data = _tar_bytes(entries)
    compressed = gzip.compress(tar_data)
    return _fixture_from_bytes(
        root,
        "tar-gzip-truncated.tgz",
        compressed[:100],
        tar_entries={"complete.txt": b"complete payload"},
    )


def _build_tar_bzip2_truncated_keeps_complete_member(root: Path) -> MatrixFixture:
    entries = {
        "complete.txt": b"complete payload",
        "truncated.bin": bytes(range(256)) * 4096,
    }
    tar_data = _tar_bytes(entries)
    compressed = bz2.compress(tar_data)
    return _fixture_from_bytes(
        root,
        "tar-bzip2-truncated.tbz2",
        compressed[: max(64, len(compressed) * 9 // 10)],
        tar_entries={"complete.txt": b"complete payload"},
    )


def _build_tar_xz_truncated_keeps_complete_member(root: Path) -> MatrixFixture:
    tar_prefix = _partial_tar_prefix()
    compressed = lzma.compress(tar_prefix, format=lzma.FORMAT_XZ)
    return _fixture_from_bytes(
        root,
        "tar-xz-truncated.txz",
        compressed[:-12],
        tar_entries={"first.bin": b"first payload"},
    )


def _build_tar_zstd_truncated_keeps_complete_member(root: Path) -> MatrixFixture:
    zstd = pytest.importorskip("zstandard")
    tar_prefix = _partial_tar_prefix()
    compressed = zstd.ZstdCompressor().compress(tar_prefix)
    return _fixture_from_bytes(
        root,
        "tar-zstd-truncated.tzst",
        compressed,
        tar_entries={"first.bin": b"first payload"},
    )


def _partial_tar_prefix() -> bytes:
    first = _tar_member("first.bin", b"first payload")
    second = _tar_member("second.bin", _pseudo_random_payload(64 * 1024))
    return first + second[:512 + 128]


def _tar_member(name: str, payload: bytes) -> bytes:
    header = _tar_raw_header(name, len(payload), b"0")
    padding = b"\0" * ((512 - (len(payload) % 512)) % 512)
    return header + payload + padding


def _tar_raw_header(name: str, size: int, typeflag: bytes) -> bytes:
    header = bytearray(512)
    encoded = name.encode("utf-8")[:100]
    header[:len(encoded)] = encoded
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = f"{size:011o}\0".encode("ascii")
    header[136:148] = b"00000000000\0"
    header[148:156] = b"        "
    header[156:157] = typeflag
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(header)


def _build_gzip_footer_bad(root: Path) -> MatrixFixture:
    payload = b"gzip payload"
    data = bytearray(gzip.compress(payload))
    data[-8:] = b"\0" * 8
    return _fixture_from_bytes(root, "gzip-footer.gz", bytes(data), stream_payload=payload)


def _build_gzip_footer_bad_with_trailing_junk(root: Path) -> MatrixFixture:
    payload = b"gzip payload"
    data = bytearray(gzip.compress(payload))
    data[-8:] = b"\0" * 8
    return _fixture_from_bytes(root, "gzip-footer-tail.gz", bytes(data) + b"JUNK", stream_payload=payload)


def _build_gzip_trailing_junk(root: Path) -> MatrixFixture:
    payload = b"gzip payload"
    data = gzip.compress(payload)
    return _fixture_from_bytes(root, "gzip-tail.gz", data + b"JUNK", expected_bytes=data, stream_payload=payload)


def _build_gzip_truncated_partial(root: Path) -> MatrixFixture:
    payload = _pseudo_random_payload(512 * 1024)
    data = gzip.compress(payload)
    return _fixture_from_bytes(root, "gzip-truncated.gz", data[:len(data) * 9 // 10], stream_payload=payload)


def _build_gzip_payload_bad(root: Path) -> MatrixFixture:
    data = bytearray(gzip.compress(b"gzip payload" * 8))
    data[len(data) // 2] ^= 0x55
    return _fixture_from_bytes(root, "gzip-payload-bad.gz", bytes(data))


def _build_bzip2_trailing_junk(root: Path) -> MatrixFixture:
    payload = b"bzip2 payload"
    data = bz2.compress(payload)
    return _fixture_from_bytes(root, "bzip2-tail.bz2", data + b"JUNK", expected_bytes=data, stream_payload=payload)


def _build_bzip2_truncated_partial(root: Path) -> MatrixFixture:
    payload = _pseudo_random_payload(2 * 1024 * 1024)
    data = bz2.compress(payload)
    return _fixture_from_bytes(root, "bzip2-truncated.bz2", data[:len(data) * 9 // 10], stream_payload=payload)


def _build_bzip2_payload_bad(root: Path) -> MatrixFixture:
    data = bytearray(bz2.compress(b"bzip2 payload" * 8))
    data[len(data) // 2] ^= 0x55
    return _fixture_from_bytes(root, "bzip2-payload-bad.bz2", bytes(data))


def _build_xz_trailing_junk(root: Path) -> MatrixFixture:
    payload = b"xz payload"
    data = lzma.compress(payload, format=lzma.FORMAT_XZ)
    return _fixture_from_bytes(root, "xz-tail.xz", data + b"JUNK", expected_bytes=data, stream_payload=payload)


def _build_xz_truncated_partial(root: Path) -> MatrixFixture:
    payload = _pseudo_random_payload(1024 * 1024)
    data = lzma.compress(payload, format=lzma.FORMAT_XZ)
    return _fixture_from_bytes(root, "xz-truncated.xz", data[:len(data) * 9 // 10], stream_payload=payload)


def _build_xz_payload_bad(root: Path) -> MatrixFixture:
    data = bytearray(lzma.compress(b"xz payload" * 8, format=lzma.FORMAT_XZ))
    data[len(data) // 2] ^= 0x55
    return _fixture_from_bytes(root, "xz-payload-bad.xz", bytes(data))


def _build_zstd_trailing_junk(root: Path) -> MatrixFixture:
    zstd = pytest.importorskip("zstandard")
    payload = b"zstd payload"
    data = zstd.ZstdCompressor().compress(payload)
    return _fixture_from_bytes(root, "zstd-tail.zst", data + b"JUNK", expected_bytes=data, stream_payload=payload)


def _build_zstd_truncated_partial(root: Path) -> MatrixFixture:
    zstd = pytest.importorskip("zstandard")
    payload = _pseudo_random_payload(4 * 1024 * 1024)
    data = zstd.ZstdCompressor().compress(payload)
    return _fixture_from_bytes(root, "zstd-truncated.zst", data[:len(data) * 9 // 10], stream_payload=payload)


UNREPAIRABLE = ("unrepairable", "unsupported")


MATRIX = [
    MatrixCase("zip_trailing_junk", "zip", ("trailing_junk",), _build_zip_trailing_junk, ("repaired",), "zip_trailing_junk_trim", _verify_zip),
    MatrixCase("zip_bad_comment_length", "zip", ("comment_length_bad",), _build_zip_bad_comment_length, ("repaired",), "zip_comment_length_fix", _verify_zip),
    MatrixCase("zip_bad_cd_offset", "zip", ("central_directory_offset_bad",), _build_zip_bad_cd_offset, ("repaired",), "zip_central_directory_offset_fix", _verify_zip),
    MatrixCase("zip_bad_cd_count", "zip", ("central_directory_count_bad",), _build_zip_bad_cd_count, ("repaired",), "zip_central_directory_count_fix", _verify_zip),
    MatrixCase("zip_missing_eocd", "zip", ("eocd_bad", "central_directory_bad"), _build_zip_missing_eocd, ("repaired",), "zip_eocd_repair", _verify_zip),
    MatrixCase("zip_missing_central_directory", "zip", ("central_directory_bad", "local_header_recovery"), _build_zip_missing_cd, ("repaired", "partial"), "zip_central_directory_rebuild", _verify_zip),
    MatrixCase("zip_local_name_len_bad", "zip", ("local_header_bad", "local_header_length_bad"), _build_zip_local_name_len_bad, ("repaired",), "zip_local_header_field_repair", _verify_zip),
    MatrixCase("zip_local_size_crc_bad", "zip", ("local_header_bad", "local_header_size_bad"), _build_zip_local_size_crc_bad, ("repaired",), "zip_local_header_field_repair", _verify_zip),
    MatrixCase("zip_local_bit3_flag_bad", "zip", ("local_header_bad", "bit3_data_descriptor", "data_descriptor"), _build_zip_local_bit3_flag_bad, ("repaired",), "zip_local_header_field_repair", _verify_zip),
    MatrixCase("zip_data_descriptor", "zip", ("data_descriptor", "compressed_size_bad"), _build_zip_descriptor, ("repaired",), "zip_data_descriptor_recovery", _verify_zip),
    MatrixCase("zip64_data_descriptor", "zip", ("data_descriptor", "compressed_size_bad"), _build_zip64_descriptor, ("repaired",), "zip_data_descriptor_recovery", _verify_zip),
    MatrixCase("zip64_missing_locator", "zip", ("zip64", "zip64_locator_bad", "central_directory_bad"), _build_zip64_missing_locator, ("repaired",), "zip64_field_repair", _verify_zip),
    MatrixCase("zip64_bad_record_fields", "zip", ("zip64", "zip64_eocd_bad", "central_directory_bad"), _build_zip64_bad_record_fields, ("repaired",), "zip64_field_repair", _verify_zip),
    MatrixCase("zip64_bad_central_extra", "zip", ("zip64", "zip64_extra_bad", "central_directory_bad"), _build_zip64_bad_central_extra, ("repaired",), "zip64_field_repair", _verify_zip),
    MatrixCase("zip_multiple_directory_fields", "zip", ("central_directory_offset_bad", "central_directory_count_bad", "central_directory_bad"), _build_zip_multiple_directory_fields, ("repaired",), "zip_eocd_repair", _verify_zip),
    MatrixCase("zip_eocd_four_field_combo", "zip", ("central_directory_offset_bad", "central_directory_count_bad", "comment_length_bad", "trailing_junk", "central_directory_bad"), _build_zip_eocd_four_field_combo, ("repaired",), "zip_eocd_repair", _verify_zip),
    MatrixCase("zip_split_trailing_junk", "zip", ("trailing_junk", "boundary_unreliable"), _build_zip_split_trailing_junk, ("repaired",), "zip_trailing_junk_trim", _verify_zip),
    MatrixCase("zip_missing_split_volume_with_extra_damage", "zip", ("missing_volume", "input_truncated", "trailing_junk", "central_directory_bad", "checksum_error"), _build_zip_missing_split_volume_with_extra_damage, UNREPAIRABLE, None),
    MatrixCase("zip_sfx_prefix_tail", "zip", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_zip_sfx_prefix_tail, ("repaired", "partial"), "zip_deep_partial_recovery", _verify_zip),
    MatrixCase("zip_sfx_split_prefix_tail", "zip", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_zip_sfx_split_prefix_tail, ("repaired", "partial"), "zip_deep_partial_recovery", _verify_zip),
    MatrixCase("zip_sfx_split_prefix_tail_bad_cd", "zip", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk", "central_directory_offset_bad", "central_directory_count_bad", "central_directory_bad"), _build_zip_sfx_split_prefix_tail_bad_cd, ("repaired",), "zip_central_directory_rebuild", _verify_zip),
    MatrixCase("zip_fake_local_header_before_real_sfx", "zip", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk", "local_header_recovery"), _build_zip_fake_local_header_before_real_sfx, ("repaired", "partial"), "zip_central_directory_rebuild", _verify_zip),
    MatrixCase("zip_single_payload_crc_bad", "zip", ("checksum_error", "crc_error", "damaged"), _build_zip_single_payload_crc_bad, UNREPAIRABLE, None),
    MatrixCase("zip_one_bad_payload_one_good", "zip", ("checksum_error", "crc_error", "damaged"), _build_zip_one_bad_payload_one_good, ("partial",), "zip_entry_quarantine_rebuild", _verify_zip),
    MatrixCase("zip_partial_recovery_damaged_local_header", "zip", ("damaged", "checksum_error"), _build_zip_partial_recovery_damaged_local_header, ("partial",), "zip_partial_recovery", _verify_zip, modules=("zip_partial_recovery",)),
    MatrixCase("zip_entry_quarantine_two_bad_two_good", "zip", ("entry_payload_bad", "checksum_error", "crc_error", "damaged"), _build_zip_entry_quarantine_two_bad_two_good, ("partial",), "zip_entry_quarantine_rebuild", _verify_zip),
    MatrixCase("zip_missing_cd_multiple_local_headers_one_bad_payload", "zip", ("central_directory_bad", "local_header_recovery", "checksum_error", "crc_error", "damaged"), _build_zip_missing_cd_multiple_local_headers_one_bad_payload, ("partial",), "zip_central_directory_rebuild", _verify_zip),
    MatrixCase("zip_descriptor_payload_bad_keeps_other_descriptor_entry", "zip", ("data_descriptor", "compressed_size_bad", "checksum_error", "crc_error", "damaged"), _build_zip_descriptor_payload_bad_keeps_other_descriptor_entry, ("partial",), "zip_deep_partial_recovery", _verify_zip),
    MatrixCase("zip64_descriptor_payload_bad_keeps_other_descriptor_entry", "zip", ("data_descriptor", "compressed_size_bad", "checksum_error", "crc_error", "damaged"), _build_zip64_descriptor_payload_bad_keeps_other_descriptor_entry, ("partial",), "zip_deep_partial_recovery", _verify_zip),
    MatrixCase("zip_multi_structure_and_payload_bad", "zip", ("checksum_error", "crc_error", "damaged", "central_directory_offset_bad", "central_directory_count_bad", "comment_length_bad", "trailing_junk", "central_directory_bad"), _build_zip_multi_structure_and_payload_bad, ("partial",), "zip_central_directory_rebuild", _verify_zip),
    MatrixCase("zip_duplicate_conflict_resolver", "zip", ("duplicate_entries", "overlapping_entries", "damaged"), _build_zip_duplicate_conflict, ("partial",), "zip_conflict_resolver_rebuild", _verify_zip, modules=("zip_conflict_resolver_rebuild",)),
    MatrixCase("archive_nested_zip_payload_salvage", "zip", ("outer_container_bad", "nested_archive", "damaged"), _build_nested_zip_payload, ("partial",), "archive_nested_payload_salvage", _verify_zip, modules=("archive_nested_payload_salvage",)),
    MatrixCase("7z_trailing_junk_v04", "7z", ("trailing_junk",), _build_7z_trailing_junk_v04, ("repaired",), "seven_zip_boundary_trim", _verify_bytes),
    MatrixCase("7z_start_crc_bad_v03", "7z", ("start_header_crc_bad",), _build_7z_start_crc_bad_v03, ("repaired",), "seven_zip_start_header_crc_fix", _verify_bytes),
    MatrixCase("7z_next_crc_bad", "7z", ("next_header_crc_bad",), _build_7z_next_crc_bad, ("repaired",), "seven_zip_crc_field_repair", _verify_bytes),
    MatrixCase("7z_next_header_offset_bad", "7z", ("next_header_offset_bad", "start_header_corrupt"), _build_7z_next_header_offset_bad, ("repaired",), "seven_zip_next_header_field_repair", _verify_bytes),
    MatrixCase("7z_next_header_size_bad", "7z", ("next_header_size_bad", "start_header_corrupt"), _build_7z_next_header_size_bad, ("repaired",), "seven_zip_next_header_field_repair", _verify_bytes),
    MatrixCase("7z_start_and_next_crc_bad", "7z", ("start_header_crc_bad", "next_header_crc_bad"), _build_7z_start_and_next_crc_bad, ("repaired",), "seven_zip_crc_field_repair", _verify_bytes),
    MatrixCase("7z_crc_fields_and_trailing_junk", "7z", ("start_header_crc_bad", "next_header_crc_bad", "trailing_junk"), _build_7z_crc_fields_and_trailing_junk, ("repaired",), "seven_zip_crc_field_repair", _verify_bytes),
    MatrixCase("7z_v03_start_next_crc_and_trailing_junk", "7z", ("start_header_crc_bad", "next_header_crc_bad", "trailing_junk"), _build_7z_v03_start_next_crc_and_trailing_junk, ("repaired",), "seven_zip_crc_field_repair", _verify_bytes),
    MatrixCase("7z_sfx_prefix_tail", "7z", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_7z_sfx_prefix_tail, ("repaired",), "seven_zip_precise_boundary_repair", _verify_bytes),
    MatrixCase("7z_sfx_fake_magic_then_real_payload", "7z", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_7z_sfx_fake_magic_then_real_payload, ("repaired",), "seven_zip_precise_boundary_repair", _verify_bytes),
    MatrixCase("7z_split_trailing_junk", "7z", ("trailing_junk", "boundary_unreliable"), _build_7z_split_trailing_junk, ("repaired",), "seven_zip_boundary_trim", _verify_bytes),
    MatrixCase("7z_sfx_split_prefix_tail", "7z", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_7z_sfx_split_prefix_tail, ("repaired",), "seven_zip_precise_boundary_repair", _verify_bytes),
    MatrixCase("archive_carrier_crop_embedded_7z", "7z", ("carrier_archive", "boundary_unreliable"), _build_archive_carrier_crop_embedded_7z, ("repaired", "partial"), "archive_carrier_crop_deep_recovery", _verify_bytes, modules=("archive_carrier_crop_deep_recovery",)),
    MatrixCase("7z_payload_bad", "7z", ("checksum_error", "content_integrity_bad_or_unknown", "damaged"), _build_7z_payload_bad, UNREPAIRABLE, None),
    MatrixCase("7z_missing_split_volume", "7z", ("missing_volume", "input_truncated"), _build_7z_missing_split_volume, UNREPAIRABLE, None),
    MatrixCase("7z_missing_middle_volume_plus_crc_noise", "7z", ("missing_volume", "input_truncated", "start_header_crc_bad", "next_header_crc_bad", "trailing_junk"), _build_7z_missing_middle_volume_plus_crc_noise, UNREPAIRABLE, None),
    MatrixCase("7z_solid_block_partial_salvage", "7z", ("solid_block_damaged", "packed_stream_bad", "damaged"), _build_7z_solid_block_salvage, ("partial",), "seven_zip_solid_block_partial_salvage", _verify_zip, modules=("seven_zip_solid_block_partial_salvage",)),
    MatrixCase("rar4_trailing_junk", "rar", ("trailing_junk",), _build_rar4_trailing_junk, ("repaired",), "rar_trailing_junk_trim", _verify_bytes),
    MatrixCase("rar5_trailing_junk", "rar", ("trailing_junk",), _build_rar5_trailing_junk, ("repaired",), "rar_trailing_junk_trim", _verify_bytes),
    MatrixCase("rar4_missing_end", "rar", ("missing_end_block", "probably_truncated"), _build_rar4_missing_end, ("repaired",), "rar_end_block_repair", _verify_bytes),
    MatrixCase("rar5_missing_end", "rar", ("missing_end_block", "probably_truncated"), _build_rar5_missing_end, ("repaired",), "rar_end_block_repair", _verify_bytes),
    MatrixCase("rar5_missing_end_with_trailing_junk_single_round", "rar", ("missing_end_block", "probably_truncated", "trailing_junk", "boundary_unreliable"), _build_rar5_missing_end_with_trailing_junk, ("repaired",), "rar_end_block_repair", _verify_bytes),
    MatrixCase("rar4_sfx_prefix_tail", "rar", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_rar4_sfx_prefix_tail, ("repaired",), "rar_carrier_crop_deep_recovery", _verify_bytes),
    MatrixCase("rar5_sfx_split_prefix_tail", "rar", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_rar5_sfx_split_prefix_tail, ("repaired",), "rar_carrier_crop_deep_recovery", _verify_bytes),
    MatrixCase("rar4_split_trailing_junk", "rar", ("trailing_junk", "boundary_unreliable"), _build_rar4_split_trailing_junk, ("repaired",), "rar_trailing_junk_trim", _verify_bytes),
    MatrixCase("rar4_block_chain_trim", "rar", ("trailing_junk", "boundary_unreliable"), _build_rar4_block_chain_trim, ("repaired", "partial"), "rar_block_chain_trim", _verify_bytes, modules=("rar_block_chain_trim",)),
    MatrixCase("rar4_payload_bad", "rar", ("checksum_error", "content_integrity_bad_or_unknown", "damaged"), _build_rar4_payload_bad, UNREPAIRABLE, None),
    MatrixCase("rar5_missing_split_volume", "rar", ("missing_volume", "unexpected_end"), _build_rar5_missing_split_volume, UNREPAIRABLE, None),
    MatrixCase("rar5_file_quarantine_rebuild", "rar", ("file_block_bad", "damaged", "data_error"), _build_rar5_file_quarantine, ("partial",), "rar_file_quarantine_rebuild", _verify_bytes, modules=("rar_file_quarantine_rebuild",)),
    MatrixCase("tar_bad_checksum", "tar", ("tar_checksum_bad",), _build_tar_bad_checksum, ("repaired",), "tar_header_checksum_fix", _verify_tar),
    MatrixCase("tar_missing_zero_blocks", "tar", ("missing_end_block", "probably_truncated"), _build_tar_missing_zero_blocks, ("repaired",), "tar_trailing_zero_block_repair", _verify_tar),
    MatrixCase("tar_trailing_junk", "tar", ("trailing_junk",), _build_tar_trailing_junk, ("repaired",), "tar_trailing_junk_trim", _verify_tar),
    MatrixCase("tar_metadata_downgrade", "tar", ("pax_header_bad", "tar_metadata_bad"), _build_tar_metadata_downgrade, ("partial",), "tar_metadata_downgrade_recovery", _verify_tar),
    MatrixCase("tar_sparse_pax_longname_repair", "tar", ("gnu_longname_bad", "pax_header_bad"), _build_tar_sparse_pax_longname, ("partial",), "tar_sparse_pax_longname_repair", _verify_tar, modules=("tar_sparse_pax_longname_repair",)),
    MatrixCase("tar_payload_truncated", "tar", ("checksum_error", "damaged", "input_truncated"), _build_tar_payload_truncated, UNREPAIRABLE, None),
    MatrixCase("tar_gzip_truncated_keeps_complete_member", "tar.gz", ("input_truncated", "probably_truncated", "unexpected_end", "damaged"), _build_tar_gzip_truncated_keeps_complete_member, ("partial", "repaired"), "tar_gzip_truncated_partial_recovery", _verify_tar, modules=("tar_gzip_truncated_partial_recovery",)),
    MatrixCase("tar_bzip2_truncated_keeps_complete_member", "tar.bz2", ("input_truncated", "probably_truncated", "unexpected_end", "damaged"), _build_tar_bzip2_truncated_keeps_complete_member, ("partial", "repaired"), "tar_bzip2_truncated_partial_recovery", _verify_tar, modules=("tar_bzip2_truncated_partial_recovery",)),
    MatrixCase("tar_xz_truncated_keeps_complete_member", "tar.xz", ("input_truncated", "probably_truncated", "unexpected_end", "damaged"), _build_tar_xz_truncated_keeps_complete_member, ("partial", "repaired"), "tar_xz_truncated_partial_recovery", _verify_tar, modules=("tar_xz_truncated_partial_recovery",)),
    MatrixCase("tar_zstd_truncated_keeps_complete_member", "tar.zst", ("input_truncated", "probably_truncated", "unexpected_end", "damaged"), _build_tar_zstd_truncated_keeps_complete_member, ("partial", "repaired"), "tar_zstd_truncated_partial_recovery", _verify_tar_zstd, modules=("tar_zstd_truncated_partial_recovery",)),
    MatrixCase("gzip_footer_bad", "gzip", ("gzip_footer_bad",), _build_gzip_footer_bad, ("repaired",), "gzip_footer_fix", _verify_gzip),
    MatrixCase("gzip_footer_bad_with_trailing_junk", "gzip", ("gzip_footer_bad", "trailing_junk", "checksum_error"), _build_gzip_footer_bad_with_trailing_junk, ("repaired",), "gzip_footer_fix", _verify_gzip),
    MatrixCase("gzip_trailing_junk", "gzip", ("trailing_junk",), _build_gzip_trailing_junk, ("repaired",), "gzip_trailing_junk_trim", _verify_gzip),
    MatrixCase("gzip_truncated_partial_recovery", "gzip", ("input_truncated", "probably_truncated", "unexpected_end"), _build_gzip_truncated_partial, ("partial",), "gzip_truncated_partial_recovery", _verify_gzip_prefix, modules=("gzip_truncated_partial_recovery",)),
    MatrixCase("gzip_deflate_member_resync", "gzip", ("deflate_resync", "damaged", "data_error"), _build_gzip_deflate_member_resync, ("partial",), "gzip_deflate_member_resync", _verify_gzip),
    MatrixCase("gzip_payload_bad", "gzip", ("checksum_error", "damaged", "data_error"), _build_gzip_payload_bad, UNREPAIRABLE, None),
    MatrixCase("bzip2_trailing_junk", "bzip2", ("trailing_junk",), _build_bzip2_trailing_junk, ("repaired",), "bzip2_trailing_junk_trim", _verify_bzip2),
    MatrixCase("bzip2_truncated_partial_recovery", "bzip2", ("input_truncated", "probably_truncated", "unexpected_end"), _build_bzip2_truncated_partial, ("partial",), "bzip2_truncated_partial_recovery", _verify_bzip2_prefix, modules=("bzip2_truncated_partial_recovery",)),
    MatrixCase("bzip2_payload_bad", "bzip2", ("checksum_error", "damaged", "data_error"), _build_bzip2_payload_bad, UNREPAIRABLE, None),
    MatrixCase("xz_trailing_junk", "xz", ("trailing_junk",), _build_xz_trailing_junk, ("repaired",), "xz_trailing_junk_trim", _verify_xz),
    MatrixCase("xz_truncated_partial_recovery", "xz", ("input_truncated", "probably_truncated", "unexpected_end"), _build_xz_truncated_partial, ("partial",), "xz_truncated_partial_recovery", _verify_xz_prefix, modules=("xz_truncated_partial_recovery",)),
    MatrixCase("xz_payload_bad", "xz", ("checksum_error", "damaged", "data_error"), _build_xz_payload_bad, UNREPAIRABLE, None),
    MatrixCase("zstd_frame_salvage", "zstd", ("frame_damaged", "damaged", "data_error"), _build_zstd_frame_salvage, ("partial",), "zstd_frame_salvage", _verify_zstd),
    MatrixCase("zstd_trailing_junk", "zstd", ("trailing_junk",), _build_zstd_trailing_junk, ("repaired",), "zstd_trailing_junk_trim", _verify_zstd),
    MatrixCase("zstd_truncated_partial_recovery", "zstd", ("input_truncated", "probably_truncated", "unexpected_end"), _build_zstd_truncated_partial, ("partial",), "zstd_truncated_partial_recovery", _verify_zstd_prefix, modules=("zstd_truncated_partial_recovery",)),
]


MULTI_ROUND_MATRIX = [
    MultiRoundCase(
        "zip_eocd_then_entry_quarantine",
        "zip",
        _build_zip_eocd_then_entry_quarantine,
        (
            RepairRound(("central_directory_offset_bad", "central_directory_count_bad", "comment_length_bad", "trailing_junk", "central_directory_bad"), ("repaired",), "zip_eocd_repair", modules=("zip_eocd_repair",)),
            RepairRound(("entry_payload_bad", "checksum_error", "crc_error", "damaged"), ("partial",), "zip_entry_quarantine_rebuild", modules=("zip_entry_quarantine_rebuild",)),
        ),
        _verify_zip,
    ),
    MultiRoundCase(
        "seven_zip_crc_then_solid_salvage",
        "7z",
        _build_7z_crc_then_solid_salvage,
        (
            RepairRound(("start_header_crc_bad",), ("repaired",), "seven_zip_start_header_crc_fix", modules=("seven_zip_start_header_crc_fix",)),
            RepairRound(("solid_block_damaged", "packed_stream_bad", "damaged"), ("partial",), "seven_zip_solid_block_partial_salvage", modules=("seven_zip_solid_block_partial_salvage",)),
        ),
        _verify_zip,
    ),
    MultiRoundCase(
        "rar5_carrier_then_file_quarantine",
        "rar",
        _build_rar5_carrier_then_file_quarantine,
        (
            RepairRound(("carrier_archive", "sfx", "boundary_unreliable"), ("repaired", "partial"), "rar_carrier_crop_deep_recovery", modules=("rar_carrier_crop_deep_recovery",)),
            RepairRound(("file_block_bad", "damaged", "data_error"), ("partial",), "rar_file_quarantine_rebuild", modules=("rar_file_quarantine_rebuild",)),
        ),
        _verify_bytes,
    ),
    MultiRoundCase(
        "nested_zip_salvage_then_entry_quarantine",
        "zip",
        _build_nested_zip_then_entry_quarantine,
        (
            RepairRound(("outer_container_bad", "nested_archive", "damaged"), ("partial",), "archive_nested_payload_salvage", modules=("archive_nested_payload_salvage",)),
            RepairRound(("entry_payload_bad", "checksum_error", "crc_error", "damaged"), ("partial",), "zip_entry_quarantine_rebuild", modules=("zip_entry_quarantine_rebuild",)),
        ),
        _verify_zip,
    ),
    MultiRoundCase(
        "rar5_sfx_split_tail_then_missing_end",
        "rar",
        _build_rar5_sfx_split_tail_missing_end,
        (
            RepairRound(("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), ("repaired",), "rar_carrier_crop_deep_recovery"),
            RepairRound(("missing_end_block", "probably_truncated"), ("repaired",), "rar_end_block_repair"),
        ),
        _verify_bytes,
    ),
    MultiRoundCase(
        "rar5_fake_magic_sfx_then_real_missing_end",
        "rar",
        _build_rar5_fake_magic_sfx_then_real_missing_end,
        (
            RepairRound(("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), ("repaired",), "rar_carrier_crop_deep_recovery"),
            RepairRound(("missing_end_block", "probably_truncated"), ("repaired",), "rar_end_block_repair"),
        ),
        _verify_bytes,
    ),
    MultiRoundCase(
        "tar_checksum_then_missing_zero_blocks",
        "tar",
        _build_tar_checksum_and_missing_zero_blocks,
        (
            RepairRound(("tar_checksum_bad", "missing_end_block", "probably_truncated"), ("repaired",), "tar_header_checksum_fix"),
            RepairRound(("missing_end_block", "probably_truncated"), ("repaired",), "tar_trailing_zero_block_repair"),
        ),
        _verify_tar,
    ),
    MultiRoundCase(
        "tar_checksum_then_trailing_junk",
        "tar",
        _build_tar_checksum_and_trailing_junk,
        (
            RepairRound(("tar_checksum_bad", "trailing_junk"), ("repaired",), "tar_header_checksum_fix"),
            RepairRound(("trailing_junk", "boundary_unreliable"), ("repaired",), "tar_trailing_junk_trim"),
        ),
        _verify_tar,
    ),
]


def test_repair_matrix_is_large_enough_to_cover_format_and_damage_axes():
    formats = {case.fmt for case in MATRIX}
    matrix_modules = {case.expected_module for case in MATRIX if case.expected_module}
    assert {"zip", "7z", "rar", "tar", "gzip", "bzip2", "xz"} <= formats
    assert len(MATRIX) >= 30
    assert {
        "archive_carrier_crop_deep_recovery",
        "archive_nested_payload_salvage",
        "bzip2_truncated_partial_recovery",
        "gzip_truncated_partial_recovery",
        "rar_block_chain_trim",
        "rar_file_quarantine_rebuild",
        "seven_zip_solid_block_partial_salvage",
        "tar_bzip2_truncated_partial_recovery",
        "tar_sparse_pax_longname_repair",
        "tar_xz_truncated_partial_recovery",
        "tar_zstd_truncated_partial_recovery",
        "zip_conflict_resolver_rebuild",
        "zip_partial_recovery",
        "xz_truncated_partial_recovery",
        "zstd_trailing_junk_trim",
        "zstd_truncated_partial_recovery",
    } <= matrix_modules
    assert any(case.expected_statuses == ("unrepairable", "unsupported") for case in MATRIX)
    assert any(len(case.flags) >= 4 for case in MATRIX)
    assert any(len(case.flags) == 3 for case in MATRIX)
    assert any(len(round_spec.flags) == 2 for case in MULTI_ROUND_MATRIX for round_spec in case.rounds)


@pytest.mark.parametrize("case", MATRIX, ids=lambda case: case.case_id)
def test_repair_layer_routes_and_repairs_format_damage_matrix(tmp_path, case: MatrixCase):
    fixture = case.build(tmp_path / case.case_id)
    result = _run_matrix_repair(tmp_path, case, fixture)

    assert result.status in case.expected_statuses
    if case.expected_module is not None:
        assert result.module_name == case.expected_module

    if result.status in {"repaired", "partial"}:
        assert result.ok is True
        assert isinstance(result.repaired_input, dict)
        assert Path(result.repaired_input["path"]).is_file()
        assert case.verify is not None
        case.verify(result, fixture)
        return

    assert result.ok is False
    assert result.repaired_input is None


def test_zip_deep_partial_skips_fake_local_header_before_real_sfx(tmp_path):
    fixture = _build_zip_fake_local_header_before_real_sfx(tmp_path / "zip_fake_deep_partial")
    scheduler = RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair-workspace"),
            "stages": {"deep": True},
            "modules": [{"name": "zip_deep_partial_recovery", "enabled": True}],
            "deep": {
                "max_candidates_per_module": 4,
                "verify_candidates": False,
            },
        }
    })
    result = scheduler.repair(RepairJob(
        source_input=fixture.source_input,
        format="zip",
        confidence=0.82,
        damage_flags=["carrier_archive", "sfx", "boundary_unreliable", "trailing_junk", "local_header_recovery"],
        archive_key="zip_fake_local_header_before_real_sfx",
    ))

    assert result.status in {"repaired", "partial"}
    assert result.module_name == "zip_deep_partial_recovery"
    _verify_zip(result, fixture)


def test_tar_sparse_pax_repair_canonicalizes_before_trailing_zero_followup(tmp_path):
    fixture = _build_tar_sparse_then_trailing_zero(tmp_path / "tar_sparse_canonicalizes")
    first = _repair_scheduler(
        tmp_path,
        modules=("tar_sparse_pax_longname_repair",),
    ).repair(RepairJob(
        source_input=fixture.source_input,
        format="tar",
        confidence=0.82,
        damage_flags=["gnu_longname_bad", "pax_header_bad", "missing_end_block"],
        archive_key="tar_sparse_canonicalizes_round_1",
    ))

    assert first.ok is True
    assert first.status == "partial"
    assert first.module_name == "tar_sparse_pax_longname_repair"
    _verify_tar(first, fixture)

    second = _repair_scheduler(
        tmp_path,
        modules=("tar_trailing_zero_block_repair",),
    ).repair(RepairJob(
        source_input={"kind": "file", "path": first.repaired_input["path"]},
        format="tar",
        confidence=0.82,
        damage_flags=["missing_end_block", "probably_truncated"],
        archive_key="tar_sparse_canonicalizes_round_2",
        attempts=1,
    ))

    assert second.ok is False
    assert second.status in {"unrepairable", "unsupported"}
    assert second.repaired_input is None


@pytest.mark.parametrize("case", MULTI_ROUND_MATRIX, ids=lambda case: case.case_id)
def test_repair_layer_composes_multi_error_repairs_across_rounds(tmp_path, case: MultiRoundCase):
    fixture = case.build(tmp_path / case.case_id)
    scheduler = _repair_scheduler(tmp_path)
    source_input = fixture.source_input
    result = None

    for index, round_spec in enumerate(case.rounds, start=1):
        round_scheduler = _repair_scheduler(tmp_path, modules=round_spec.modules) if round_spec.modules else scheduler
        result = round_scheduler.repair(RepairJob(
            source_input=source_input,
            format=case.fmt,
            confidence=0.82,
            damage_flags=list(round_spec.flags),
            archive_key=f"{case.case_id}_round_{index}",
            attempts=index - 1,
        ))
        assert result.status in round_spec.expected_statuses
        assert result.module_name == round_spec.expected_module
        assert result.ok is True
        assert isinstance(result.repaired_input, dict)
        assert Path(result.repaired_input["path"]).is_file()
        source_input = {"kind": "file", "path": result.repaired_input["path"]}

    assert result is not None
    case.verify(result, fixture)
