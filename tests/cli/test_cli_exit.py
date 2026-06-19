from argparse import Namespace

from sunpack.app.cli import maybe_pause
from sunpack.app.cli_constants import EXIT_OK, EXIT_TASK_FAILED
from sunpack.app.cli_context import CliContext
from sunpack.app.cli_types import CliCommandResult


def _result(errors=None):
    return CliCommandResult(command="extract", inputs={}, summary={}, errors=errors or [])


def test_successful_extract_does_not_pause(monkeypatch, capsys):
    pause_calls = []
    monkeypatch.setattr("sunpack.app.cli.os.system", pause_calls.append)

    maybe_pause(Namespace(command="extract", pause_on_exit=True), CliContext(), EXIT_OK, _result())

    assert pause_calls == []
    assert capsys.readouterr().out == ""


def test_failed_extract_still_pauses(monkeypatch):
    pause_calls = []
    monkeypatch.setattr("sunpack.app.cli.os.system", pause_calls.append)

    maybe_pause(
        Namespace(command="extract", pause_on_exit=True),
        CliContext(),
        EXIT_TASK_FAILED,
        _result(["extraction failed"]),
    )

    assert len(pause_calls) == 1
