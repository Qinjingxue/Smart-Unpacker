from packrelic.app.cli_reporter import CliReporter
from packrelic.app.cli_types import CliCommandResult


def test_reporter_applies_color_when_forced(capsys):
    reporter = CliReporter(color="always")
    reporter.info("[CLI] hello")
    reporter.error("[CLI] bad")

    captured = capsys.readouterr()

    assert "\033[36m[CLI] hello\033[0m" in captured.out
    assert "\033[31m[CLI] bad\033[0m" in captured.err


def test_reporter_never_colors_json_output(capsys):
    reporter = CliReporter(json_mode=True, color="always")
    reporter.emit_result(CliCommandResult(command="x", inputs={}, summary={}, errors=[]))

    captured = capsys.readouterr()

    assert "\033[" not in captured.out
    assert '"command": "x"' in captured.out


def test_reporter_respects_no_color_environment(monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    reporter = CliReporter(color="always")
    reporter.info("[CLI] hello")

    captured = capsys.readouterr()

    assert "\033[" not in captured.out
    assert "[CLI] hello" in captured.out
