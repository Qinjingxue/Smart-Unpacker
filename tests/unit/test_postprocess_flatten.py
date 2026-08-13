import sunpack.postprocess.internal.flatten as flatten_module
from sunpack.config.schema import normalize_config
from sunpack.postprocess.actions import PostProcessActions
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


def test_postprocess_flatten_output_uses_chinese_language(tmp_path, capsys):
    target = tmp_path / "extract_out"
    child = target / "only_child"
    child.mkdir(parents=True)
    (child / "payload.txt").write_text("ok", encoding="utf-8")

    PostProcessActions(normalize_config({"verification": {}}), language="zh").apply(
        cleanup_archives=False,
        flatten_outputs=True,
        flatten_targets=[str(target)],
    )

    output = capsys.readouterr().out
    assert "正在压平单子目录" in output
    assert "Flattening single-branch directories" not in output
