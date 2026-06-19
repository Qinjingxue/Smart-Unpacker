from types import SimpleNamespace

from sunpack.coordinator.reporting import RunReporter


def _task(path):
    return SimpleNamespace(main_path=str(path), logical_name=path.stem)


def _outcome(out_dir, *, success=True, partial=False, error=""):
    return SimpleNamespace(
        success=success,
        result=SimpleNamespace(success=success, out_dir=str(out_dir), error=error),
        verification=SimpleNamespace(decision_hint="accept_partial" if partial else "accept"),
    )


def test_progress_displays_nested_archive_parent_chain_and_final_page(tmp_path, capsys):
    reporter = RunReporter("zh")
    outer = _task(tmp_path / "outer.zip")
    outer_output = tmp_path / "outer"

    reporter.scan_started(1)
    reporter.begin_round(1, [outer])
    reporter.task_started(outer, 1)
    reporter.task_finished(outer, _outcome(outer_output), 1)

    inner = _task(outer_output / "folder" / "inner.7z")
    inner_output = outer_output / "folder" / "inner"
    reporter.begin_round(2, [inner])
    reporter.task_started(inner, 2)
    reporter.task_finished(inner, _outcome(inner_output), 2)
    reporter.log_final_summary(str(tmp_path), 0, 2, [])

    output = capsys.readouterr().out
    assert "[扫描中] 正在查找压缩包…" in output
    assert "[扫描完成] 发现 1 个待处理压缩包" in output
    assert "[递归扫描] 第 2 层发现 1 个嵌套压缩包" in output
    assert "└─ [成功 2/2] inner.7z（来自 outer.zip）" in output
    assert "完整成功：2  部分恢复：0  失败：0" in output
    assert "递归层级：2 层，处理嵌套包：1 个" in output
    assert f"输出位置：{outer_output}" in output


def test_progress_displays_full_lineage_for_deep_recursion(tmp_path, capsys):
    reporter = RunReporter("zh")
    paths = [
        (tmp_path / "outer.zip", tmp_path / "outer"),
        (tmp_path / "outer" / "inner.rar", tmp_path / "outer" / "inner"),
        (tmp_path / "outer" / "inner" / "data.7z", tmp_path / "outer" / "inner" / "data"),
    ]

    for depth, (archive, output_dir) in enumerate(paths, start=1):
        task = _task(archive)
        reporter.begin_round(depth, [task])
        reporter.task_finished(task, _outcome(output_dir), depth)

    output = capsys.readouterr().out
    assert "data.7z（来自 outer.zip > inner.rar）" in output


def test_quiet_progress_writes_failure_log_without_terminal_output(tmp_path, capsys):
    reporter = RunReporter("zh", quiet=True)
    bad = _task(tmp_path / "bad.zip")

    reporter.begin_round(1, [bad])
    reporter.task_started(bad, 1)
    reporter.task_finished(bad, _outcome(tmp_path / "bad", success=False, error="broken"), 1)
    reporter.log_final_summary(str(tmp_path), 0, 0, ["bad.zip [broken]"])

    assert capsys.readouterr().out == ""
    assert (tmp_path / "failed_log.txt").read_text(encoding="utf-8") == "bad.zip [broken]\n"
