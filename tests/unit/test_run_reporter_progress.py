import io
from types import SimpleNamespace

import sunpack.coordinator.reporting as reporting
from sunpack.contracts.failures import FailureInfo, FailureKind
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


def test_partial_recovery_prints_possible_missing_volume_warning(tmp_path, capsys):
    warning = FailureInfo(
        FailureKind.MISSING_VOLUME,
        "extraction_report",
        "压缩包内容不完整；可能缺少一个或多个分卷",
        details={"missing_volume_confirmed": False, "partial_recovery": True},
    )

    RunReporter("zh").log_final_summary(
        str(tmp_path),
        0,
        0,
        [],
        recovered_outputs=[{
            "archive": str(tmp_path / "sample.zip.001"),
            "completeness": 0.75,
            "warning": warning.to_dict(),
        }],
        failures=[warning],
    )

    output = capsys.readouterr().out
    assert "[部分恢复] sample.zip.001" in output
    assert "[警告] 压缩包内容不完整；可能缺少一个或多个分卷" in output


def test_interactive_panel_updates_fixed_row_with_progress_and_colors(tmp_path, monkeypatch):
    stream = io.StringIO()
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: True)
    monkeypatch.setattr(reporting.sys, "stdout", stream)
    reporter = RunReporter("zh")
    task = _task(tmp_path / "large.7z")

    reporter.begin_round(1, [task])
    reporter.task_started(task, 1)
    reporter._last_render_at = 0.0
    reporter.task_progress(task, {"completed_bytes": 50, "total_bytes": 100})
    reporter.task_status(task, "repairing")
    reporter.task_finished(task, _outcome(tmp_path / "large"), 1)

    output = stream.getvalue()
    assert "等待队列" in output
    assert "50%" in output
    assert "正在修复" in output
    assert "\033[32m" in output and "完成" in output
    assert "\033[1A" in output


def test_forwarded_terminal_capability_does_not_require_server_console():
    stream = io.StringIO()
    stream.isatty = lambda: True
    stream.supports_terminal_updates = True

    assert reporting._terminal_supports_updates(stream)


def test_noninteractive_terminal_streams_throttled_progress_bar(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(reporting, "_terminal_supports_updates", lambda _stream: False)
    reporter = RunReporter("zh")
    task = _task(tmp_path / "large.7z")

    reporter.begin_round(1, [task])
    reporter.task_progress(task, {"completed_bytes": 5, "total_bytes": 100})
    reporter.task_progress(task, {"completed_bytes": 9, "total_bytes": 100})
    reporter.task_progress(task, {"completed_bytes": 50, "total_bytes": 100})

    output = capsys.readouterr().out
    assert output.count("正在解压") == 2
    assert "  5%" in output
    assert " 50%" in output
