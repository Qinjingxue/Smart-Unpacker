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


def test_zip_fast_verifier_reads_complete_raw_split_stream(tmp_path):
    archive_path = _create_encrypted_zip_archive(tmp_path, "split-secret", "AES256")
    payload = archive_path.read_bytes()
    cut = max(1, len(payload) // 2)
    part_paths = [tmp_path / "split.zip.001", tmp_path / "split.zip.002"]
    part_paths[0].write_bytes(payload[:cut])
    part_paths[1].write_bytes(payload[cut:])
    archive_input = {
        "kind": "archive_input",
        "entry_path": str(part_paths[0]),
        "open_mode": "native_volumes",
        "format_hint": "zip",
        "volume_style": "numeric_suffix",
        "parts": [
            {
                "path": str(path),
                "role": "first" if index == 1 else "member",
                "volume_number": index,
                "canonical_name": path.name,
            }
            for index, path in enumerate(part_paths, 1)
        ],
    }

    outcome = ZipFastVerifier().verify_batch(
        str(part_paths[0]),
        ["wrong", "split-secret"],
        part_paths=[str(path) for path in part_paths],
        archive_input=archive_input,
    )

    assert outcome.ok is True
    assert outcome.matched_index == 1


def test_zip_fast_verifier_uses_disk_numbers_for_spanned_archive(tmp_path):
    archive_path = _create_encrypted_zip_archive(tmp_path, "spanned-secret", "AES256")
    payload = bytearray(archive_path.read_bytes())
    name_len = int.from_bytes(payload[26:28], "little")
    extra_len = int.from_bytes(payload[28:30], "little")
    data_offset = 30 + name_len + extra_len
    cut = data_offset + 5  # Split the AES salt itself across two disks.
    eocd = payload.rfind(b"PK\x05\x06")
    assert eocd > cut
    central_offset = int.from_bytes(payload[eocd + 16:eocd + 20], "little")
    assert central_offset > cut
    payload[eocd + 4:eocd + 6] = (1).to_bytes(2, "little")
    payload[eocd + 6:eocd + 8] = (1).to_bytes(2, "little")
    payload[eocd + 16:eocd + 20] = (central_offset - cut).to_bytes(4, "little")
    first = tmp_path / "spanned.z01"
    terminal = tmp_path / "spanned.zip"
    first.write_bytes(payload[:cut])
    terminal.write_bytes(payload[cut:])
    archive_input = {
        "kind": "archive_input",
        "entry_path": str(first),
        "open_mode": "native_volumes",
        "format_hint": "zip",
        "volume_style": "zip_spanned",
        "parts": [
            {"path": str(first), "role": "first", "volume_number": 1, "canonical_name": first.name},
            {"path": str(terminal), "role": "terminal", "volume_number": 2, "canonical_name": terminal.name},
        ],
    }

    outcome = ZipFastVerifier().verify_batch(
        str(first),
        ["wrong", "spanned-secret"],
        part_paths=[str(first), str(terminal)],
        archive_input=archive_input,
    )

    assert outcome.ok is True
    assert outcome.matched_index == 1


def test_zip_fast_verifier_finds_encrypted_entry_after_clear_entry(tmp_path):
    seven_zip = _require_7z_or_skip()
    public = tmp_path / "public.txt"
    secret = tmp_path / "secret.txt"
    public.write_text("public", encoding="utf-8")
    secret.write_text("secret", encoding="utf-8")
    archive = tmp_path / "mixed.zip"
    first = subprocess.run(
        [str(seven_zip), "a", str(archive), str(public), "-tzip", "-y"],
        capture_output=True,
        text=True,
    )
    second = subprocess.run(
        [str(seven_zip), "a", str(archive), str(secret), "-tzip", "-mem=AES256", "-pmixed-secret", "-y"],
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0, first.stderr or first.stdout
    assert second.returncode == 0, second.stderr or second.stdout

    outcome = ZipFastVerifier().verify_batch(str(archive), ["wrong", "mixed-secret"])

    assert outcome.ok is True
    assert outcome.matched_index == 1


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
