from __future__ import annotations

import pytest

from sunpack.support.runtime_mode import (
    RUNTIME_MODE_CLI,
    RUNTIME_MODE_WATCH,
    consume_runtime_mode,
    runtime_mode_argument,
)


def test_runtime_mode_defaults_to_cli_without_mutating_other_arguments():
    assert consume_runtime_mode(["extract", "archive.zip"]) == (
        RUNTIME_MODE_CLI,
        ["extract", "archive.zip"],
    )


def test_runtime_mode_selects_watch_and_strips_only_private_argument():
    assert consume_runtime_mode(
        ["--once", runtime_mode_argument(RUNTIME_MODE_WATCH), "--no-tray"]
    ) == (RUNTIME_MODE_WATCH, ["--once", "--no-tray"])


@pytest.mark.parametrize(
    "argv",
    [
        ["--_sunpack-mode=watch", "--_sunpack-mode=cli"],
        ["--_sunpack-mode=unknown"],
        ["--_sunpack-mode="],
    ],
)
def test_runtime_mode_rejects_duplicate_or_invalid_values(argv):
    with pytest.raises(ValueError):
        consume_runtime_mode(argv)


def test_runtime_mode_parser_is_process_launch_local():
    assert consume_runtime_mode(["--_sunpack-mode=watch"])[0] == RUNTIME_MODE_WATCH
    assert consume_runtime_mode(["--persistent-server"])[0] == RUNTIME_MODE_CLI
