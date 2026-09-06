from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks import watch_broker


def test_isolated_broker_environment_requires_matching_test_names(monkeypatch) -> None:
    monkeypatch.setenv(watch_broker.SERVICE_ENV, "SunPackWatchBrokerTest_example")
    monkeypatch.setenv(watch_broker.PIPE_ENV, r"\\.\pipe\SunPack.WatchBroker.Test.example")
    assert watch_broker.isolated_broker_environment()

    monkeypatch.setenv(watch_broker.SERVICE_ENV, "SunPackWatchBroker")
    assert not watch_broker.isolated_broker_environment()


def test_temporary_watch_broker_service_installs_and_always_uninstalls(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "sunpack-watch-broker.exe"
    binary.touch()
    actions: list[tuple[str, str, str, Path]] = []
    monkeypatch.setattr(watch_broker, "_ensure_watch_broker_binary", lambda: binary)
    monkeypatch.setattr(watch_broker, "_binary_sha256", lambda _path: "a" * 64)
    monkeypatch.setattr(
        watch_broker,
        "_run_service_manager",
        lambda action, service_name, pipe_name, path: actions.append(
            (action, service_name, pipe_name, path)
        ),
    )
    monkeypatch.setenv(watch_broker.SERVICE_ENV, "original-service")

    with pytest.raises(RuntimeError, match="scenario failed"):
        with watch_broker.temporary_watch_broker_service():
            assert watch_broker.isolated_broker_environment()
            assert Path(watch_broker.os.environ[watch_broker.BINARY_ENV]) == binary
            assert watch_broker.os.environ[watch_broker.HASH_ENV] == "a" * 64
            raise RuntimeError("scenario failed")

    assert [action for action, *_ in actions] == ["Install", "Uninstall"]
    assert actions[0][1:] == actions[1][1:]
    assert watch_broker.os.environ[watch_broker.SERVICE_ENV] == "original-service"
    assert watch_broker.PIPE_ENV not in watch_broker.os.environ
    assert watch_broker.BINARY_ENV not in watch_broker.os.environ
    assert watch_broker.HASH_ENV not in watch_broker.os.environ
