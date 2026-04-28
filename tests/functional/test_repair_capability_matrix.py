from __future__ import annotations

import bz2
from dataclasses import dataclass, field
import gzip
import io
import lzma
from pathlib import Path
import struct
import tarfile
from typing import Callable
import zipfile
import zlib

import pytest

from smart_unpacker.repair import RepairJob, RepairResult, RepairScheduler


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


@dataclass(frozen=True)
class RepairRound:
    flags: tuple[str, ...]
    expected_statuses: tuple[str, ...]
    expected_module: str


@dataclass(frozen=True)
class MultiRoundCase:
    case_id: str
    fmt: str
    build: BuildFn
    rounds: tuple[RepairRound, ...]
    verify: VerifyFn


def _run_matrix_repair(tmp_path: Path, case: MatrixCase, fixture: MatrixFixture) -> RepairResult:
    scheduler = _repair_scheduler(tmp_path)
    return scheduler.repair(RepairJob(
        source_input=fixture.source_input,
        format=case.fmt,
        confidence=0.82,
        damage_flags=list(case.flags),
        archive_key=case.case_id,
    ))


def _repair_scheduler(tmp_path: Path) -> RepairScheduler:
    return RepairScheduler({
        "repair": {
            "workspace": str(tmp_path / "repair-workspace"),
            "max_modules_per_job": 8,
            "stages": {"deep": True},
            "deep": {
                "max_candidates_per_module": 4,
                "verify_candidates": False,
            },
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


def _build_rar4_payload_bad(root: Path) -> MatrixFixture:
    data = bytearray(_rar4_bytes(file_payload=b"payload"))
    payload_offset = data.index(b"payload")
    data[payload_offset] ^= 0x55
    return _fixture_from_bytes(root, "rar4-payload-bad.rar", bytes(data))


def _build_rar5_missing_split_volume(root: Path) -> MatrixFixture:
    data = RAR5_MAGIC + _rar5_block(1) + _rar5_block(2, data=b"payload")
    return _fixture_from_bytes(root, "rar5-missing-volume.part1.rar", data)


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


def _build_gzip_payload_bad(root: Path) -> MatrixFixture:
    data = bytearray(gzip.compress(b"gzip payload" * 8))
    data[len(data) // 2] ^= 0x55
    return _fixture_from_bytes(root, "gzip-payload-bad.gz", bytes(data))


def _build_bzip2_trailing_junk(root: Path) -> MatrixFixture:
    payload = b"bzip2 payload"
    data = bz2.compress(payload)
    return _fixture_from_bytes(root, "bzip2-tail.bz2", data + b"JUNK", expected_bytes=data, stream_payload=payload)


def _build_bzip2_payload_bad(root: Path) -> MatrixFixture:
    data = bytearray(bz2.compress(b"bzip2 payload" * 8))
    data[len(data) // 2] ^= 0x55
    return _fixture_from_bytes(root, "bzip2-payload-bad.bz2", bytes(data))


def _build_xz_trailing_junk(root: Path) -> MatrixFixture:
    payload = b"xz payload"
    data = lzma.compress(payload, format=lzma.FORMAT_XZ)
    return _fixture_from_bytes(root, "xz-tail.xz", data + b"JUNK", expected_bytes=data, stream_payload=payload)


def _build_xz_payload_bad(root: Path) -> MatrixFixture:
    data = bytearray(lzma.compress(b"xz payload" * 8, format=lzma.FORMAT_XZ))
    data[len(data) // 2] ^= 0x55
    return _fixture_from_bytes(root, "xz-payload-bad.xz", bytes(data))


UNREPAIRABLE = ("unrepairable", "unsupported")


MATRIX = [
    MatrixCase("zip_trailing_junk", "zip", ("trailing_junk",), _build_zip_trailing_junk, ("repaired",), "zip_trailing_junk_trim", _verify_zip),
    MatrixCase("zip_bad_comment_length", "zip", ("comment_length_bad",), _build_zip_bad_comment_length, ("repaired",), "zip_comment_length_fix", _verify_zip),
    MatrixCase("zip_bad_cd_offset", "zip", ("central_directory_offset_bad",), _build_zip_bad_cd_offset, ("repaired",), "zip_central_directory_offset_fix", _verify_zip),
    MatrixCase("zip_bad_cd_count", "zip", ("central_directory_count_bad",), _build_zip_bad_cd_count, ("repaired",), "zip_central_directory_count_fix", _verify_zip),
    MatrixCase("zip_missing_eocd", "zip", ("eocd_bad", "central_directory_bad"), _build_zip_missing_eocd, ("repaired",), "zip_eocd_repair", _verify_zip),
    MatrixCase("zip_missing_central_directory", "zip", ("central_directory_bad", "local_header_recovery"), _build_zip_missing_cd, ("repaired", "partial"), "zip_central_directory_rebuild", _verify_zip),
    MatrixCase("zip_data_descriptor", "zip", ("data_descriptor", "compressed_size_bad"), _build_zip_descriptor, ("repaired",), "zip_data_descriptor_recovery", _verify_zip),
    MatrixCase("zip64_data_descriptor", "zip", ("data_descriptor", "compressed_size_bad"), _build_zip64_descriptor, ("repaired",), "zip_data_descriptor_recovery", _verify_zip),
    MatrixCase("zip_multiple_directory_fields", "zip", ("central_directory_offset_bad", "central_directory_count_bad", "central_directory_bad"), _build_zip_multiple_directory_fields, ("repaired",), "zip_eocd_repair", _verify_zip),
    MatrixCase("zip_eocd_four_field_combo", "zip", ("central_directory_offset_bad", "central_directory_count_bad", "comment_length_bad", "trailing_junk", "central_directory_bad"), _build_zip_eocd_four_field_combo, ("repaired",), "zip_eocd_repair", _verify_zip),
    MatrixCase("zip_split_trailing_junk", "zip", ("trailing_junk", "boundary_unreliable"), _build_zip_split_trailing_junk, ("repaired",), "zip_trailing_junk_trim", _verify_zip),
    MatrixCase("zip_missing_split_volume_with_extra_damage", "zip", ("missing_volume", "input_truncated", "trailing_junk", "central_directory_bad", "checksum_error"), _build_zip_missing_split_volume_with_extra_damage, UNREPAIRABLE, None),
    MatrixCase("zip_sfx_prefix_tail", "zip", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_zip_sfx_prefix_tail, ("repaired", "partial"), "zip_deep_partial_recovery", _verify_zip),
    MatrixCase("zip_sfx_split_prefix_tail", "zip", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_zip_sfx_split_prefix_tail, ("repaired", "partial"), "zip_deep_partial_recovery", _verify_zip),
    MatrixCase("zip_sfx_split_prefix_tail_bad_cd", "zip", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk", "central_directory_offset_bad", "central_directory_count_bad", "central_directory_bad"), _build_zip_sfx_split_prefix_tail_bad_cd, ("repaired",), "zip_central_directory_rebuild", _verify_zip),
    MatrixCase("zip_fake_local_header_before_real_sfx", "zip", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk", "local_header_recovery"), _build_zip_fake_local_header_before_real_sfx, ("repaired", "partial"), "zip_central_directory_rebuild", _verify_zip),
    MatrixCase("zip_single_payload_crc_bad", "zip", ("checksum_error", "crc_error", "damaged"), _build_zip_single_payload_crc_bad, UNREPAIRABLE, None),
    MatrixCase("zip_one_bad_payload_one_good", "zip", ("checksum_error", "crc_error", "damaged"), _build_zip_one_bad_payload_one_good, ("partial",), "zip_deep_partial_recovery", _verify_zip),
    MatrixCase("zip_missing_cd_multiple_local_headers_one_bad_payload", "zip", ("central_directory_bad", "local_header_recovery", "checksum_error", "crc_error", "damaged"), _build_zip_missing_cd_multiple_local_headers_one_bad_payload, ("partial",), "zip_central_directory_rebuild", _verify_zip),
    MatrixCase("zip_descriptor_payload_bad_keeps_other_descriptor_entry", "zip", ("data_descriptor", "compressed_size_bad", "checksum_error", "crc_error", "damaged"), _build_zip_descriptor_payload_bad_keeps_other_descriptor_entry, ("partial",), "zip_deep_partial_recovery", _verify_zip),
    MatrixCase("zip64_descriptor_payload_bad_keeps_other_descriptor_entry", "zip", ("data_descriptor", "compressed_size_bad", "checksum_error", "crc_error", "damaged"), _build_zip64_descriptor_payload_bad_keeps_other_descriptor_entry, ("partial",), "zip_deep_partial_recovery", _verify_zip),
    MatrixCase("zip_multi_structure_and_payload_bad", "zip", ("checksum_error", "crc_error", "damaged", "central_directory_offset_bad", "central_directory_count_bad", "comment_length_bad", "trailing_junk", "central_directory_bad"), _build_zip_multi_structure_and_payload_bad, ("partial",), "zip_central_directory_rebuild", _verify_zip),
    MatrixCase("7z_trailing_junk_v04", "7z", ("trailing_junk",), _build_7z_trailing_junk_v04, ("repaired",), "seven_zip_boundary_trim", _verify_bytes),
    MatrixCase("7z_start_crc_bad_v03", "7z", ("start_header_crc_bad",), _build_7z_start_crc_bad_v03, ("repaired",), "seven_zip_start_header_crc_fix", _verify_bytes),
    MatrixCase("7z_next_crc_bad", "7z", ("next_header_crc_bad",), _build_7z_next_crc_bad, ("repaired",), "seven_zip_crc_field_repair", _verify_bytes),
    MatrixCase("7z_start_and_next_crc_bad", "7z", ("start_header_crc_bad", "next_header_crc_bad"), _build_7z_start_and_next_crc_bad, ("repaired",), "seven_zip_crc_field_repair", _verify_bytes),
    MatrixCase("7z_crc_fields_and_trailing_junk", "7z", ("start_header_crc_bad", "next_header_crc_bad", "trailing_junk"), _build_7z_crc_fields_and_trailing_junk, ("repaired",), "seven_zip_crc_field_repair", _verify_bytes),
    MatrixCase("7z_v03_start_next_crc_and_trailing_junk", "7z", ("start_header_crc_bad", "next_header_crc_bad", "trailing_junk"), _build_7z_v03_start_next_crc_and_trailing_junk, ("repaired",), "seven_zip_crc_field_repair", _verify_bytes),
    MatrixCase("7z_sfx_prefix_tail", "7z", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_7z_sfx_prefix_tail, ("repaired",), "seven_zip_precise_boundary_repair", _verify_bytes),
    MatrixCase("7z_sfx_fake_magic_then_real_payload", "7z", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_7z_sfx_fake_magic_then_real_payload, ("repaired",), "seven_zip_precise_boundary_repair", _verify_bytes),
    MatrixCase("7z_split_trailing_junk", "7z", ("trailing_junk", "boundary_unreliable"), _build_7z_split_trailing_junk, ("repaired",), "seven_zip_boundary_trim", _verify_bytes),
    MatrixCase("7z_sfx_split_prefix_tail", "7z", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_7z_sfx_split_prefix_tail, ("repaired",), "seven_zip_precise_boundary_repair", _verify_bytes),
    MatrixCase("7z_payload_bad", "7z", ("checksum_error", "content_integrity_bad_or_unknown", "damaged"), _build_7z_payload_bad, UNREPAIRABLE, None),
    MatrixCase("7z_missing_split_volume", "7z", ("missing_volume", "input_truncated"), _build_7z_missing_split_volume, UNREPAIRABLE, None),
    MatrixCase("7z_missing_middle_volume_plus_crc_noise", "7z", ("missing_volume", "input_truncated", "start_header_crc_bad", "next_header_crc_bad", "trailing_junk"), _build_7z_missing_middle_volume_plus_crc_noise, UNREPAIRABLE, None),
    MatrixCase("rar4_trailing_junk", "rar", ("trailing_junk",), _build_rar4_trailing_junk, ("repaired",), "rar_trailing_junk_trim", _verify_bytes),
    MatrixCase("rar5_trailing_junk", "rar", ("trailing_junk",), _build_rar5_trailing_junk, ("repaired",), "rar_trailing_junk_trim", _verify_bytes),
    MatrixCase("rar4_missing_end", "rar", ("missing_end_block", "probably_truncated"), _build_rar4_missing_end, ("repaired",), "rar_end_block_repair", _verify_bytes),
    MatrixCase("rar5_missing_end", "rar", ("missing_end_block", "probably_truncated"), _build_rar5_missing_end, ("repaired",), "rar_end_block_repair", _verify_bytes),
    MatrixCase("rar5_missing_end_with_trailing_junk_single_round", "rar", ("missing_end_block", "probably_truncated", "trailing_junk", "boundary_unreliable"), _build_rar5_missing_end_with_trailing_junk, ("repaired",), "rar_end_block_repair", _verify_bytes),
    MatrixCase("rar4_sfx_prefix_tail", "rar", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_rar4_sfx_prefix_tail, ("repaired",), "rar_carrier_crop_deep_recovery", _verify_bytes),
    MatrixCase("rar5_sfx_split_prefix_tail", "rar", ("carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"), _build_rar5_sfx_split_prefix_tail, ("repaired",), "rar_carrier_crop_deep_recovery", _verify_bytes),
    MatrixCase("rar4_split_trailing_junk", "rar", ("trailing_junk", "boundary_unreliable"), _build_rar4_split_trailing_junk, ("repaired",), "rar_trailing_junk_trim", _verify_bytes),
    MatrixCase("rar4_payload_bad", "rar", ("checksum_error", "content_integrity_bad_or_unknown", "damaged"), _build_rar4_payload_bad, UNREPAIRABLE, None),
    MatrixCase("rar5_missing_split_volume", "rar", ("missing_volume", "unexpected_end"), _build_rar5_missing_split_volume, UNREPAIRABLE, None),
    MatrixCase("tar_bad_checksum", "tar", ("tar_checksum_bad",), _build_tar_bad_checksum, ("repaired",), "tar_header_checksum_fix", _verify_tar),
    MatrixCase("tar_missing_zero_blocks", "tar", ("missing_end_block", "probably_truncated"), _build_tar_missing_zero_blocks, ("repaired",), "tar_trailing_zero_block_repair", _verify_tar),
    MatrixCase("tar_trailing_junk", "tar", ("trailing_junk",), _build_tar_trailing_junk, ("repaired",), "tar_trailing_junk_trim", _verify_tar),
    MatrixCase("tar_payload_truncated", "tar", ("checksum_error", "damaged", "input_truncated"), _build_tar_payload_truncated, UNREPAIRABLE, None),
    MatrixCase("tar_gzip_truncated_keeps_complete_member", "tar.gz", ("input_truncated", "probably_truncated", "unexpected_end", "damaged"), _build_tar_gzip_truncated_keeps_complete_member, ("partial", "repaired"), "tar_gzip_truncated_partial_recovery", _verify_tar),
    MatrixCase("gzip_footer_bad", "gzip", ("gzip_footer_bad",), _build_gzip_footer_bad, ("repaired",), "gzip_footer_fix", _verify_gzip),
    MatrixCase("gzip_footer_bad_with_trailing_junk", "gzip", ("gzip_footer_bad", "trailing_junk", "checksum_error"), _build_gzip_footer_bad_with_trailing_junk, ("repaired",), "gzip_footer_fix", _verify_gzip),
    MatrixCase("gzip_trailing_junk", "gzip", ("trailing_junk",), _build_gzip_trailing_junk, ("repaired",), "gzip_trailing_junk_trim", _verify_gzip),
    MatrixCase("gzip_payload_bad", "gzip", ("checksum_error", "damaged", "data_error"), _build_gzip_payload_bad, UNREPAIRABLE, None),
    MatrixCase("bzip2_trailing_junk", "bzip2", ("trailing_junk",), _build_bzip2_trailing_junk, ("repaired",), "bzip2_trailing_junk_trim", _verify_bzip2),
    MatrixCase("bzip2_payload_bad", "bzip2", ("checksum_error", "damaged", "data_error"), _build_bzip2_payload_bad, UNREPAIRABLE, None),
    MatrixCase("xz_trailing_junk", "xz", ("trailing_junk",), _build_xz_trailing_junk, ("repaired",), "xz_trailing_junk_trim", _verify_xz),
    MatrixCase("xz_payload_bad", "xz", ("checksum_error", "damaged", "data_error"), _build_xz_payload_bad, UNREPAIRABLE, None),
]


MULTI_ROUND_MATRIX = [
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
    assert {"zip", "7z", "rar", "tar", "gzip", "bzip2", "xz"} <= formats
    assert len(MATRIX) >= 30
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


@pytest.mark.parametrize("case", MULTI_ROUND_MATRIX, ids=lambda case: case.case_id)
def test_repair_layer_composes_multi_error_repairs_across_rounds(tmp_path, case: MultiRoundCase):
    fixture = case.build(tmp_path / case.case_id)
    scheduler = _repair_scheduler(tmp_path)
    source_input = fixture.source_input
    result = None

    for index, round_spec in enumerate(case.rounds, start=1):
        result = scheduler.repair(RepairJob(
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
