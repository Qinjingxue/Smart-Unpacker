from __future__ import annotations

import os

import pytest

from scripts import run_unelevated_process


def test_explicit_environment_overrides_are_forwarded_to_child(monkeypatch):
    monkeypatch.setenv("SUNPACK_EXISTING_TEST_VALUE", "original")
    args = run_unelevated_process.parse_args(
        [
            "--cwd",
            ".",
            "--env",
            "SUNPACK_EXISTING_TEST_VALUE=overridden",
            "--env",
            r"SUNPACK_PIPE_TEST_VALUE=\\.\pipe\SunPack.Test",
            "--",
            "python",
        ]
    )

    environment = run_unelevated_process._child_environment(args)

    assert environment["SUNPACK_EXISTING_TEST_VALUE"] == "overridden"
    assert environment["SUNPACK_PIPE_TEST_VALUE"] == r"\\.\pipe\SunPack.Test"
    assert environment is not os.environ


def test_invalid_environment_override_is_rejected():
    with pytest.raises(SystemExit):
        run_unelevated_process.parse_args(
            ["--cwd", ".", "--env", "missing-separator", "--", "python"]
        )
