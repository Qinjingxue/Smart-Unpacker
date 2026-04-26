import subprocess

from smart_unpacker.detection.pipeline.processors.modules.confirmation import seven_zip_probe
from smart_unpacker.detection.pipeline.processors.modules.confirmation import seven_zip_validation
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.support.external_command_cache import clear_cache_namespace


class _Context:
    def __init__(self, path: str):
        self.fact_bag = FactBag()
        self.fact_bag.set("file.path", path)


def _result(stdout: str = "", stderr: str = "", returncode: int = 2):
    return subprocess.CompletedProcess(["7z"], returncode, stdout, stderr)


def test_probe_does_not_confirm_random_file_named_archive(tmp_path, monkeypatch):
    clear_cache_namespace("external_command")
    target = tmp_path / "fake.7z"
    target.write_bytes(b"x" * 128)
    output = """
Listing archive: fake.7z

ERROR: fake.7z
Open ERROR: Cannot open the file as [7z] archive

ERRORS:
Is not archive
"""

    monkeypatch.setattr(seven_zip_probe, "get_7z_path", lambda: "7z")
    monkeypatch.setattr(seven_zip_probe.subprocess, "run", lambda *args, **kwargs: _result(stderr=output))

    probe = seven_zip_probe.process_7z_probe(_Context(str(target)))

    assert probe["type"] == "7z"
    assert probe["is_archive"] is False
    assert probe["is_broken"] is False


def test_probe_marks_truncated_archive_as_broken_archive_like(tmp_path, monkeypatch):
    clear_cache_namespace("external_command")
    target = tmp_path / "broken.7z"
    target.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"x" * 128)
    output = """
Listing archive: broken.7z

ERROR: broken.7z
Open ERROR: Cannot open the file as [7z] archive

ERRORS:
Unexpected end of archive
"""

    monkeypatch.setattr(seven_zip_probe, "get_7z_path", lambda: "7z")
    monkeypatch.setattr(seven_zip_probe.subprocess, "run", lambda *args, **kwargs: _result(stderr=output))

    probe = seven_zip_probe.process_7z_probe(_Context(str(target)))

    assert probe["type"] == "7z"
    assert probe["is_archive"] is False
    assert probe["is_broken"] is True


def test_validation_treats_password_prompt_as_encrypted(tmp_path, monkeypatch):
    clear_cache_namespace("external_command")
    target = tmp_path / "encrypted.7z"
    target.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"x" * 128)
    output = """
Testing archive: encrypted.7z

Enter password (will not be echoed):

Break signaled
"""

    monkeypatch.setattr(seven_zip_validation, "get_7z_path", lambda: "7z")
    monkeypatch.setattr(seven_zip_validation.subprocess, "run", lambda *args, **kwargs: _result(stderr=output))

    validation = seven_zip_validation.process_7z_validation(_Context(str(target)))

    assert validation["ok"] is False
    assert validation["encrypted"] is True
