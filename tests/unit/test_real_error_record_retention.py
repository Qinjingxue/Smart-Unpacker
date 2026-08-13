from types import SimpleNamespace

from tests.real import conftest as real_conftest


def test_real_error_records_are_append_only_and_unique(tmp_path, monkeypatch):
    monkeypatch.setattr(real_conftest, "ERROR_RECORDS_DIR", tmp_path)

    previous = tmp_path / "previous_failure.txt"
    previous.write_text("keep this failure", encoding="utf-8")
    real_conftest.pytest_sessionstart(None)
    assert previous.read_text(encoding="utf-8") == "keep this failure"

    item = SimpleNamespace(
        nodeid="tests/real/example.py::test_example",
        _plan_error_info={"attempt": 1},
    )
    report = SimpleNamespace(
        capstdout="stdout",
        capstderr="stderr",
        duration=0.1,
        longreprtext="failure",
    )
    real_conftest._write_error_record(item, report)
    real_conftest._write_error_record(item, report)

    all_text_files = sorted(tmp_path.glob("*.txt"))
    records = [
        path
        for path in all_text_files
        if path.name not in {previous.name, "index.txt"}
    ]
    assert previous in all_text_files
    assert len(records) == 2
    assert len((tmp_path / "index.txt").read_text(encoding="utf-8").splitlines()) == 2

    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    real_conftest.pytest_sessionstart(None)
    assert previous.read_text(encoding="utf-8") == "keep this failure"
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == readme
