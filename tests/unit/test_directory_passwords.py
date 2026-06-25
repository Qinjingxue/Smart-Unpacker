from types import SimpleNamespace

from sunpack.contracts.detection import FactBag
from sunpack.coordinator.extraction_batch import ExtractionBatchRunner
from sunpack.passwords.internal.clipboard import _plausible_passwords
from sunpack.passwords.internal.local_files import (
    DIRECTORY_PASSWORD_CONTEXT_FACT,
    discover_directory_passwords_for_archive,
)


def test_discovers_same_directory_txt_passwords(tmp_path):
    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"not really an archive")
    (tmp_path / "D.txt").write_text("# comment\nouter-secret\n\n", encoding="utf-8")

    assert discover_directory_passwords_for_archive(str(archive), {}) == ["outer-secret"]


def test_directory_password_context_inherits_and_extends(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    child = tmp_path / "parent" / "child"
    child.mkdir()
    archive = child / "nested.zip"
    archive.write_bytes(b"not really an archive")
    (child / "G.txt").write_text("inner-secret\nouter-secret\n", encoding="utf-8")

    runner = object.__new__(ExtractionBatchRunner)
    runner.config = {}
    runner._directory_password_contexts = {
        __import__("os").path.normcase(__import__("os").path.abspath(str(parent))): ["outer-secret"],
    }
    task = SimpleNamespace(main_path=str(archive), fact_bag=FactBag())

    runner._annotate_directory_password_contexts([task])

    assert task.fact_bag.get(DIRECTORY_PASSWORD_CONTEXT_FACT) == ["outer-secret", "inner-secret"]


def test_clipboard_password_filter_rejects_obvious_non_text_payloads():
    assert _plausible_passwords(["ok", "bad\x00value", "x" * 600], max_password_length=512) == ["ok"]
