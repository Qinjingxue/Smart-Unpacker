import sunpack.postprocess.internal.flatten as flatten_module
from sunpack.postprocess.internal.flatten import DirectoryFlattener


def test_flatten_reports_native_errors(monkeypatch, capsys):
    native_result = {
        "moved": 1,
        "removed_dirs": 0,
        "errors": [r"C:\source\child -> C:\target\child: Access is denied"],
    }
    monkeypatch.setattr(
        flatten_module,
        "_native_flatten_single_branch_directories",
        lambda _base: native_result,
    )

    result = DirectoryFlattener("en").flatten_dirs(r"C:\target")

    output = capsys.readouterr().out
    assert result == native_result
    assert r"C:\source\child -> C:\target\child: Access is denied" in output
