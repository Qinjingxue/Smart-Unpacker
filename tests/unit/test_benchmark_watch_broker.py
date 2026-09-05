from __future__ import annotations

import hashlib

from benchmarks import watch_broker


def test_isolated_broker_environment_requires_matching_test_names(monkeypatch) -> None:
    monkeypatch.setenv(watch_broker.SERVICE_ENV, "SunPackWatchBrokerTest_example")
    monkeypatch.setenv(watch_broker.PIPE_ENV, r"\\.\pipe\SunPack.WatchBroker.Test.example")
    assert watch_broker.isolated_broker_environment()

    monkeypatch.setenv(watch_broker.SERVICE_ENV, "SunPackWatchBroker")
    assert not watch_broker.isolated_broker_environment()


def test_broker_binary_hash_uses_the_actual_binary_when_not_declared(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "sunpack-watch-broker.exe"
    binary.write_bytes(b"workspace broker")
    monkeypatch.delenv(watch_broker.HASH_ENV, raising=False)

    assert watch_broker._binary_sha256(str(binary)) == hashlib.sha256(b"workspace broker").hexdigest()
