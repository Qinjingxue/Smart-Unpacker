import subprocess

import pytest

from sunpack.passwords.verifier.zip_fast import ZipFastVerifier
from tests.helpers.tool_config import get_test_tools


def _require_7z_or_skip():
    seven_zip = get_test_tools()["seven_zip"]
    if not seven_zip or not seven_zip.is_file():
        pytest.skip("7z.exe is required for ZIP fast verifier fixtures")
    return seven_zip


def _create_encrypted_zip_archive(tmp_path, password: str, method: str):
    seven_zip = _require_7z_or_skip()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "payload.txt").write_text("zip aes payload", encoding="utf-8")
    archive_path = tmp_path / f"{method.lower()}.zip"
    result = subprocess.run(
        [
            str(seven_zip),
            "a",
            str(archive_path),
            str(source_dir / "payload.txt"),
            "-tzip",
            f"-mem={method}",
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


def test_zip_fast_verifier_matches_winzip_aes_password(tmp_path):
    archive_path = _create_encrypted_zip_archive(tmp_path, "secret", "AES256")

    outcome = ZipFastVerifier().verify_batch(str(archive_path), ["bad", "secret"])

    assert outcome.ok is True
    assert outcome.status == "match"
    assert outcome.matched_index == 1
    assert outcome.matched_indices == (1,)
    assert outcome.attempts == 2
    assert outcome.match_evidence == "winzip_aes_password_verifier"


def test_zip_fast_verifier_marks_zipcrypto_header_match_as_inconclusive_evidence(tmp_path):
    archive_path = _create_encrypted_zip_archive(tmp_path, "secret", "ZipCrypto")

    outcome = ZipFastVerifier().verify_batch(str(archive_path), ["bad", "secret"])

    assert outcome.ok is True
    assert outcome.status == "match"
    assert outcome.matched_index == 1
    assert outcome.matched_indices == (1,)
    assert outcome.match_evidence == "zipcrypto_header_byte"


def test_zip_fast_verifier_rejects_wrong_winzip_aes_passwords(tmp_path):
    archive_path = _create_encrypted_zip_archive(tmp_path, "secret", "AES256")

    outcome = ZipFastVerifier().verify_batch(str(archive_path), ["bad1", "bad2"])

    assert outcome.ok is False
    assert outcome.status == "no_match"
    assert outcome.attempts == 2
