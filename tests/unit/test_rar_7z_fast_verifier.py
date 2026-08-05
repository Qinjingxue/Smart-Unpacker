import subprocess
import zlib

import pytest

from sunpack.passwords.verifier.rar_fast import RarFastVerifier
from sunpack.passwords.verifier.seven_zip_fast import SevenZipFastVerifier
from tests.helpers.tool_config import get_test_tools


def _raw_split_input(tmp_path, archive, *, format_hint: str):
    payload = archive.read_bytes()
    cut1 = max(1, len(payload) // 3)
    cut2 = max(cut1 + 1, (len(payload) * 2) // 3)
    chunks = [payload[:cut1], payload[cut1:cut2], payload[cut2:]]
    parts = []
    for index, chunk in enumerate(chunks, 1):
        path = tmp_path / f"split.{format_hint}.{index:03d}"
        path.write_bytes(chunk)
        parts.append({
            "path": str(path),
            "role": "first" if index == 1 else "member",
            "volume_number": index,
            "canonical_name": path.name,
        })
    return {
        "kind": "archive_input",
        "entry_path": parts[0]["path"],
        "open_mode": "native_volumes",
        "format_hint": format_hint,
        "volume_style": "numeric_suffix",
        "parts": parts,
    }


def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _rar5_encryption_header_fixture() -> bytes:
    salt = bytes.fromhex("8246bf4a50c80674189774196e0551b3")
    password_check = bytes.fromhex("c0fa7586afb0c24c")
    body = b"".join([
        _vint(4),
        _vint(0),
        _vint(0),
        _vint(1),
        bytes([15]),
        salt,
        password_check,
        b"\0\0\0\0",
    ])
    crc_payload = _vint(len(body)) + body
    crc = zlib.crc32(crc_payload) & 0xFFFFFFFF
    return b"Rar!\x1a\x07\x01\x00" + crc.to_bytes(4, "little") + crc_payload


def _rar3_hp_encrypted_header_fixture() -> bytes:
    salt = bytes.fromhex("45109af8ab5f297a")
    encrypted_header = bytes.fromhex("adbf6c5385d7a40373e8f77d7b89d317")
    return b"Rar!\x1a\x07\x00" + salt + encrypted_header


def test_rar_fast_verifier_matches_rar3_hp_encrypted_header(tmp_path):
    archive = tmp_path / "sample.rar"
    archive.write_bytes(_rar3_hp_encrypted_header_fixture())

    outcome = RarFastVerifier().verify_batch(str(archive), ["wrong", "hashcat"])

    assert outcome.ok is True
    assert outcome.status == "match"
    assert outcome.matched_index == 1
    assert outcome.attempts == 2


def test_rar_fast_verifier_rejects_wrong_rar3_hp_encrypted_header(tmp_path):
    archive = tmp_path / "sample.rar"
    archive.write_bytes(_rar3_hp_encrypted_header_fixture())

    outcome = RarFastVerifier().verify_batch(str(archive), ["wrong1", "wrong2"])

    assert outcome.ok is False
    assert outcome.status == "no_match"
    assert outcome.attempts == 2


def test_rar_fast_verifier_matches_rar5_password_check(tmp_path):
    archive = tmp_path / "sample.rar"
    archive.write_bytes(_rar5_encryption_header_fixture())

    outcome = RarFastVerifier().verify_batch(str(archive), ["wrong", "U0b7258526OROQY"])

    assert outcome.ok is True
    assert outcome.status == "match"
    assert outcome.matched_index == 1
    assert outcome.attempts == 2


def test_rar_fast_verifier_rejects_wrong_rar5_password_check(tmp_path):
    archive = tmp_path / "sample.rar"
    archive.write_bytes(_rar5_encryption_header_fixture())

    outcome = RarFastVerifier().verify_batch(str(archive), ["wrong1", "wrong2"])

    assert outcome.ok is False
    assert outcome.status == "no_match"
    assert outcome.attempts == 2


def test_rar_fast_verifier_reads_complete_raw_split_stream(tmp_path):
    archive = tmp_path / "source.rar"
    archive.write_bytes(_rar5_encryption_header_fixture())
    archive_input = _raw_split_input(tmp_path, archive, format_hint="rar")

    outcome = RarFastVerifier().verify_batch(
        archive_input["entry_path"],
        ["wrong", "U0b7258526OROQY"],
        part_paths=[part["path"] for part in archive_input["parts"]],
        archive_input=archive_input,
    )

    assert outcome.ok is True
    assert outcome.matched_index == 1


def test_rar_fast_verifier_uses_structured_first_volume(tmp_path):
    first = tmp_path / "archive.part1.rar"
    second = tmp_path / "archive.part2.rar"
    first.write_bytes(_rar5_encryption_header_fixture())
    second.write_bytes(b"Rar!\x1a\x07\x01\x00trailing-volume")
    archive_input = {
        "kind": "archive_input",
        "entry_path": str(first),
        "open_mode": "native_volumes",
        "format_hint": "rar",
        "volume_style": "rar_part",
        "parts": [
            {"path": str(first), "role": "first", "volume_number": 1, "canonical_name": first.name},
            {"path": str(second), "role": "member", "volume_number": 2, "canonical_name": second.name},
        ],
    }

    outcome = RarFastVerifier().verify_batch(
        str(first),
        ["wrong", "U0b7258526OROQY"],
        part_paths=[str(first), str(second)],
        archive_input=archive_input,
    )

    assert outcome.ok is True
    assert outcome.matched_index == 1


def test_rar_fast_verifier_parallel_batch_preserves_first_match(tmp_path):
    archive = tmp_path / "sample.rar"
    archive.write_bytes(_rar5_encryption_header_fixture())
    passwords = [f"wrong-{index}" for index in range(40)]
    passwords[23] = "U0b7258526OROQY"
    passwords[37] = "U0b7258526OROQY"

    outcome = RarFastVerifier().verify_batch(str(archive), passwords)

    assert outcome.ok is True
    assert outcome.status == "match"
    assert outcome.matched_index == 23
    assert outcome.attempts == 24

    rejected = RarFastVerifier().verify_batch(
        str(archive), [f"definitely-wrong-{index}" for index in range(40)]
    )
    assert rejected.ok is False
    assert rejected.status == "no_match"
    assert rejected.attempts == 40


def _require_7z_or_skip():
    seven_zip = get_test_tools()["seven_zip"]
    if not seven_zip or not seven_zip.is_file():
        pytest.skip("7z.exe is required for 7z fast verifier fixtures")
    return seven_zip


def _create_encrypted_header_7z(tmp_path, password: str, compression: str = "0"):
    seven_zip = _require_7z_or_skip()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "payload.txt").write_text("7z encrypted header payload", encoding="utf-8")
    archive_path = tmp_path / "encrypted.7z"
    result = subprocess.run(
        [
            str(seven_zip),
            "a",
            str(archive_path),
            str(source_dir / "payload.txt"),
            f"-mx={compression}",
            "-mhe=on",
            f"-p{password}",
            "-y",
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"7z failed:\n{result.stdout}\n{result.stderr}")
    return archive_path


def test_seven_zip_fast_verifier_matches_encrypted_header_password(tmp_path):
    archive = _create_encrypted_header_7z(tmp_path, "secret")

    outcome = SevenZipFastVerifier().verify_batch(str(archive), ["bad", "secret"])

    assert outcome.ok is True
    assert outcome.status == "match"
    assert outcome.matched_index == 1
    assert outcome.attempts == 2


def test_seven_zip_fast_verifier_rejects_wrong_encrypted_header_passwords(tmp_path):
    archive = _create_encrypted_header_7z(tmp_path, "secret")

    outcome = SevenZipFastVerifier().verify_batch(str(archive), ["bad1", "bad2"])

    assert outcome.ok is False
    assert outcome.status == "no_match"
    assert outcome.attempts == 2


def test_seven_zip_fast_verifier_reads_complete_raw_split_stream(tmp_path):
    archive = _create_encrypted_header_7z(tmp_path, "split-secret", "5")
    archive_input = _raw_split_input(tmp_path, archive, format_hint="7z")

    outcome = SevenZipFastVerifier().verify_batch(
        archive_input["entry_path"],
        ["wrong", "split-secret"],
        part_paths=[part["path"] for part in archive_input["parts"]],
        archive_input=archive_input,
    )

    assert outcome.ok is True
    assert outcome.matched_index == 1


def test_seven_zip_fast_verifier_defers_callback_volume_family(tmp_path):
    first = tmp_path / "archive.part1.rar"
    second = tmp_path / "archive.part2.rar"
    first.write_bytes(b"not-read")
    second.write_bytes(b"not-read")
    archive_input = {
        "kind": "archive_input",
        "entry_path": str(first),
        "open_mode": "native_volumes",
        "format_hint": "7z",
        "volume_style": "rar_part",
        "parts": [
            {"path": str(first), "role": "first", "volume_number": 1, "canonical_name": first.name},
            {"path": str(second), "role": "member", "volume_number": 2, "canonical_name": second.name},
        ],
    }

    outcome = SevenZipFastVerifier().verify_batch(
        str(first), ["secret"], part_paths=[str(first), str(second)], archive_input=archive_input
    )

    assert outcome.status == "unknown_needs_final_verifier"
    assert outcome.attempts == 0


def test_seven_zip_fast_verifier_parallel_batch_preserves_first_match(tmp_path):
    archive = _create_encrypted_header_7z(tmp_path, "secret")
    passwords = [f"bad-{index}" for index in range(40)]
    passwords[19] = "secret"
    passwords[35] = "secret"

    outcome = SevenZipFastVerifier().verify_batch(str(archive), passwords)

    assert outcome.ok is True
    assert outcome.status == "match"
    assert outcome.matched_index == 19
    assert outcome.attempts == 20

    rejected = SevenZipFastVerifier().verify_batch(
        str(archive), [f"definitely-bad-{index}" for index in range(40)]
    )
    assert rejected.ok is False
    assert rejected.status == "no_match"
    assert rejected.attempts == 40


@pytest.mark.parametrize("compression", ["0", "5"])
def test_seven_zip_fast_verifier_matches_unicode_password_across_header_coders(
    tmp_path, compression
):
    password = "密碼-🔐-пароль"
    archive = _create_encrypted_header_7z(tmp_path, password, compression)
    candidates = [f"错误-{index}" for index in range(12)] + [password]

    outcome = SevenZipFastVerifier().verify_batch(str(archive), candidates)

    assert outcome.ok is True
    assert outcome.status == "match"
    assert outcome.matched_index == 12
    assert outcome.attempts == 13


def test_seven_zip_fast_verifier_uses_same_probe_for_embedded_range(tmp_path):
    password = "range-secret"
    archive = _create_encrypted_header_7z(tmp_path, password, "5")
    prefix = b"carrier-prefix" * 37
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(prefix + archive.read_bytes() + b"carrier-tail")
    archive_input = {
        "kind": "archive_input",
        "entry_path": str(carrier),
        "open_mode": "file_range",
        "format_hint": "7z",
        "parts": [
            {
                "path": str(carrier),
                "start": len(prefix),
                "end": len(prefix) + archive.stat().st_size,
            }
        ],
    }

    outcome = SevenZipFastVerifier().verify_batch(
        str(carrier), ["wrong", password], archive_input=archive_input
    )

    assert outcome.ok is True
    assert outcome.matched_index == 1
    assert outcome.attempts == 2
