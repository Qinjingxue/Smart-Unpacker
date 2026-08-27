from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace

from sunpack.cli.runtime_host import RuntimeHost
from sunpack.coordinator.archive_registry import ActiveArchiveRegistry


def test_archive_registry_detects_watch_owner_by_file_identity(tmp_path):
    archive = tmp_path / "archive.zip"
    alias = tmp_path / "alias.zip"
    archive.write_bytes(b"zip")
    os.link(archive, alias)
    registry = ActiveArchiveRegistry()

    assert registry.reserve("watch-job", "watch", [str(archive)]) is None
    conflict = registry.reserve("cli-job", "foreground", [str(alias)])

    assert conflict is not None
    assert conflict.origin == "watch"
    registry.release("watch-job")
    assert registry.reserve("cli-job", "foreground", [str(alias)]) is None


def test_extract_reports_watch_busy_without_starting_another_task(tmp_path):
    from sunpack.cli.commands import extract
    from sunpack.cli.runtime_state import set_runtime_host

    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"zip")
    registry = ActiveArchiveRegistry()
    assert registry.reserve("watch-job", "watch", [str(archive)]) is None
    set_runtime_host(SimpleNamespace(archive_registry=registry))
    try:
        code, result = asyncio.run(
            extract.handle(
                SimpleNamespace(paths=[str(archive)]),
                SimpleNamespace(
                    cwd=str(tmp_path),
                    reporter=None,
                    t=lambda key, **_kwargs: "该任务已由 watch 处理，请等待" if key == "cli.watch_busy" else key,
                ),
            )
        )
    finally:
        set_runtime_host(None)

    assert code != 0
    assert result.summary["status"] == "watch_busy"
    assert result.errors == ["该任务已由 watch 处理，请等待"]


def test_runtime_host_owns_watch_and_switches_host_and_worker_qos(monkeypatch):
    import sunpack.cli.runtime_host as runtime_host_module
    import sunpack.cli.persistent_runtime as persistent_runtime
    import sunpack.platform.windows.process_qos as process_qos

    events = []

    class FakeEngine:
        async def set_process_mode(self, *, background):
            events.append(("worker_qos", background))

    engine = FakeEngine()

    class FakeService:
        def __init__(self, *, pipeline_engine, **_kwargs):
            assert pipeline_engine is engine
            self.scheduler = None
            self._stop = asyncio.Event()
            self.reloads = 0

        async def run(self, *, initial_scan=False):
            events.append(("watch_started", initial_scan))
            await self._stop.wait()
            return 0

        async def wait_ready(self):
            while not any(event[0] == "watch_started" for event in events):
                await asyncio.sleep(0)

        def request_stop(self):
            self._stop.set()

        async def reload(self):
            self.reloads += 1

    async def shared_engine(_config):
        return engine

    monkeypatch.setattr(runtime_host_module, "load_config", lambda: {})
    monkeypatch.setattr(runtime_host_module, "shared_pipeline_engine", shared_engine)
    monkeypatch.setattr(runtime_host_module, "WatchService", FakeService)
    monkeypatch.setattr(persistent_runtime, "current_pipeline_engine", lambda: engine)
    monkeypatch.setattr(process_qos, "set_processing_mode", lambda *, background: events.append(("host_qos", background)))

    async def scenario():
        host = RuntimeHost()
        started = await host.start_watch(tray_enabled=False, initial_scan=True)
        assert started["started"] is True
        assert host.watch_enabled is True
        assert (await host.reload_watch())["reloaded"] is True
        await host._set_process_mode(background=True)
        await host.foreground_started()
        await host.foreground_finished()
        stopped = await host.stop_watch()
        assert stopped["stopped"] is True
        assert host.watch_enabled is False
        await host.close()

    asyncio.run(scenario())
    assert ("worker_qos", True) in events
    assert ("host_qos", True) in events
    assert ("worker_qos", False) in events
    assert ("host_qos", False) in events
