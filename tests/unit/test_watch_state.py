import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock

import sunpack.filesystem.watcher.state as watch_state_module
from sunpack.filesystem.watcher.state import WatchStateStore


def test_independent_state_stores_use_unique_atomic_writers(tmp_path, monkeypatch):
    state_path = tmp_path / "state.json"
    stores = [WatchStateStore(str(state_path)), WatchStateStore(str(state_path))]
    barrier = Barrier(len(stores))
    replace_lock = Lock()
    temporary_paths = []
    real_replace = watch_state_module.os.replace

    def synchronized_replace(source, destination):
        temporary_paths.append(source)
        barrier.wait()
        with replace_lock:
            real_replace(source, destination)

    monkeypatch.setattr(watch_state_module.os, "replace", synchronized_replace)

    with ThreadPoolExecutor(max_workers=len(stores)) as executor:
        list(executor.map(lambda store: store.save(), stores))

    assert len(set(temporary_paths)) == len(stores)
    assert all(path.parent == tmp_path and path.name.endswith(".tmp") for path in temporary_paths)
    assert json.loads(state_path.read_text(encoding="utf-8"))["version"] > 0
    assert not list(tmp_path.glob(".state.json.*.tmp"))


def test_input_snapshot_persists_and_matches_only_identical_stable_input(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))

    state.record_attempt(str(archive), stat.st_size, stat.st_mtime, "device:inode")
    state.complete_work([str(archive)])

    reloaded = WatchStateStore(str(state_path))
    assert reloaded.snapshot_matches(str(archive), stat.st_size, stat.st_mtime, "device:inode")
    assert not reloaded.snapshot_matches(str(archive), stat.st_size, stat.st_mtime, "different")
    assert not reloaded.pending_snapshots()


def test_input_snapshot_persists_usn_and_rejects_new_usn_with_same_metadata(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))

    state.record_attempt(str(archive), stat.st_size, stat.st_mtime, "file-id", 101)
    state.complete_work([str(archive)])
    reloaded = WatchStateStore(str(state_path))

    assert reloaded.snapshot_matches(str(archive), stat.st_size, stat.st_mtime, "file-id", 101)
    assert not reloaded.snapshot_matches(str(archive), stat.st_size, stat.st_mtime, "file-id", 102)


def test_departure_removes_snapshot_so_identical_input_is_new_again(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state.record_attempt(str(archive), stat.st_size, stat.st_mtime, "device:inode")
    state.complete_work([str(archive)])

    assert state.forget_path(str(archive))
    assert not state.snapshot_matches(str(archive), stat.st_size, stat.st_mtime, "device:inode")


def test_pending_work_survives_restart_until_completed(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))
    state.record_attempt(str(archive), stat.st_size, stat.st_mtime, "device:inode")

    reloaded = WatchStateStore(str(state_path))
    assert [item.path for item in reloaded.pending_snapshots()] == [str(archive.resolve())]

    reloaded.complete_work([str(archive)])
    assert not WatchStateStore(str(state_path)).pending_snapshots()


def test_only_retry_blocking_failures_are_kept_as_entries(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state.mark(
        str(archive),
        stat.st_size,
        stat.st_mtime,
        status="failed_password",
        failure_payload={"kind": "wrong_password", "blockers": ["password"]},
    )
    assert state.latest_entry_for_path(str(archive)).status == "failed_password"

    state.mark(str(archive), stat.st_size, stat.st_mtime, status="done")
    assert state.latest_entry_for_path(str(archive)) is None


def test_previous_state_schema_is_intentionally_not_loaded(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"version": 5, "entries": {"legacy": {"status": "done"}}}), encoding="utf-8")

    state = WatchStateStore(str(state_path))

    assert not state.snapshots


def test_previous_watch_group_schema_is_not_loaded_after_field_migration(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({
        "version": watch_state_module.STATE_VERSION - 2,
        "groups": {
            "group": {
                "group_id": "group",
                "directory": str(tmp_path),
                "logical_name": "archive",
                "split_family": "7z_numbered",
                "head_path": str(tmp_path / "archive.7z.001"),
                "member_paths": [str(tmp_path / "archive.7z.001")],
                "relation_fingerprint": "legacy",
                "last_attempted_fingerprint": "legacy",
            }
        },
    }), encoding="utf-8")

    state = WatchStateStore(str(state_path))

    assert not state.groups


def test_legacy_successful_group_is_discarded_during_lifecycle_state_migration(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({
        "version": watch_state_module.STATE_VERSION - 1,
        "groups": {
            "group": {
                "group_id": "group",
                "directory": str(tmp_path),
                "logical_name": "archive",
                "split_family": "7z_numbered",
                "head_path": str(tmp_path / "archive.7z.001"),
                "input_paths": [str(tmp_path / "archive.7z.001")],
                "owned_paths": [str(tmp_path / "archive.7z.001")],
                "status": "done",
                "input_fingerprint": "old-input",
                "ownership_fingerprint": "old-ownership",
                "last_attempted_input_fingerprint": "old-input",
            }
        },
    }), encoding="utf-8")

    state = WatchStateStore(str(state_path))

    assert not state.groups
    assert json.loads(state_path.read_text(encoding="utf-8"))["version"] == watch_state_module.STATE_VERSION


def test_active_work_persists_force_cause_for_restart(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"active")
    state = WatchStateStore(str(state_path))
    candidate = type("Candidate", (), {
        "path": str(archive),
        "size": archive.stat().st_size,
        "mtime": archive.stat().st_mtime,
    })()
    state.queue_active(candidate, force=True)

    [pending] = WatchStateStore(str(state_path)).pending_snapshots()
    assert pending.path == str(archive.resolve())
    assert pending.force is True
