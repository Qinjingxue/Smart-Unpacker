import subprocess
import zlib

import pytest

from packrelic.passwords.verifier.rar_fast import RarFastVerifier
from packrelic.passwords.verifier.seven_zip_fast import SevenZipFastVerifier
from tests.helpers.tool_config import get_test_tools


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


def _require_7z_or_skip():
    seven_zip = get_test_tools()["seven_zip"]
    if not seven_zip or not seven_zip.is_file():
        pytest.skip("7z.exe is required for 7z fast verifier fixtures")
    return seven_zip


def _create_encrypted_header_7z(tmp_path, password: str):
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
            "-mx=0",
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
