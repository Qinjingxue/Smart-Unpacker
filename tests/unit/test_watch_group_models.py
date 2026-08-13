from sunpack.filesystem.watcher.group_models import (
    BLOCKER_PASSWORD,
    WatchGroupSnapshot,
    WatchGroupState,
)
from sunpack.filesystem.watcher.group_dispatch import plan_watch_dispatches
from sunpack.filesystem.watcher.scanner import WatchCandidate
from sunpack.filesystem.watcher.state import WatchStateStore
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.support.path_keys import path_key


def _snapshot(fingerprint: str, ownership_fingerprint: str | None = None) -> WatchGroupSnapshot:
    ownership_fingerprint = ownership_fingerprint or fingerprint
    return WatchGroupSnapshot(
        group_id="group",
        directory="/downloads",
        logical_name="archive",
        split_family="7z_numbered",
        head_path="/downloads/archive.7z.001",
        input_paths=("/downloads/archive.7z.001",),
        companion_paths=(),
        owned_paths=("/downloads/archive.7z.001",),
        input_fingerprint=fingerprint,
        ownership_fingerprint=ownership_fingerprint,
        complete=None,
    )


def test_password_blocker_retries_when_split_group_input_changes():
    state = WatchGroupState(
        group_id="group",
        directory="/downloads",
        logical_name="archive",
        split_family="7z_numbered",
        head_path="/downloads/archive.7z.001",
        blockers=[BLOCKER_PASSWORD],
        last_attempted_input_fingerprint="old",
        password_generation=4,
    )

    assert state.retry_ready(_snapshot("new"), password_generation=4) is True
    assert state.retry_ready(_snapshot("old"), password_generation=4) is False
    assert state.retry_ready(_snapshot("old"), password_generation=5) is True


def test_companion_arrival_changes_ownership_without_restarting_same_input():
    state = WatchGroupState(
        group_id="group",
        directory="/downloads",
        logical_name="archive",
        split_family="7z_numbered",
        head_path="/downloads/archive.7z.001",
        status="done",
        last_attempted_input_fingerprint="same-input",
    )

    snapshot = _snapshot("same-input", ownership_fingerprint="launcher-arrived")

    assert state.retry_ready(snapshot, password_generation=0) is False


def test_watch_snapshot_uses_relation_owned_paths_for_launcher_events(tmp_path):
    launcher = tmp_path / "archive.exe"
    first = tmp_path / "archive.7z.001"
    second = tmp_path / "archive.7z.002"
    launcher.write_bytes(b"MZ")
    first.write_bytes(b"volume 1")
    second.write_bytes(b"volume 2")

    resolved = WatchGroupCoordinator({}).resolve_paths([str(launcher)])
    snapshot = resolved[path_key(str(launcher))]

    assert snapshot is not None
    assert snapshot.head_path == str(first.resolve())
    assert snapshot.input_paths == (str(first.resolve()), str(second.resolve()))
    assert snapshot.companion_paths == (str(launcher.resolve()),)
    assert snapshot.owned_paths == (
        str(first.resolve()),
        str(second.resolve()),
        str(launcher.resolve()),
    )


def test_watch_dispatch_treats_launcher_as_active_group_path(tmp_path):
    launcher = tmp_path / "archive.exe"
    first = tmp_path / "archive.7z.001"
    launcher.write_bytes(b"MZ")
    first.write_bytes(b"volume 1")
    snapshot = WatchGroupSnapshot(
        group_id="group",
        directory=str(tmp_path),
        logical_name="archive",
        split_family="7z_numbered",
        head_path=str(first),
        input_paths=(str(first),),
        companion_paths=(str(launcher),),
        owned_paths=(str(first), str(launcher)),
        input_fingerprint="input",
        ownership_fingerprint="owned",
        complete=None,
    )

    class Resolver:
        def resolve_paths(self, paths):
            return {path_key(path): snapshot for path in paths}

    candidate = WatchCandidate(str(launcher), launcher.stat().st_size, launcher.stat().st_mtime)
    dispatches, waiting, deferred = plan_watch_dispatches(
        [candidate],
        active_paths={path_key(str(launcher))},
        coordinator=Resolver(),
        state=WatchStateStore(str(tmp_path / "state.json")),
        prepare_candidate=lambda _path: candidate,
    )

    assert dispatches == []
    assert waiting == []
    assert [item.candidate.path for item in deferred] == [str(launcher)]
