import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Lock

import sunpack.filesystem.watcher.state as watch_state_module
from sunpack.filesystem.watcher.group_models import WatchGroupState
from sunpack.filesystem.watcher.state import WatchStateStore


def _group_state(tmp_path, name, paths, *, head_path=None, status="done"):
    normalized = [str(path.resolve()) for path in paths]
    selected_head = (paths[0] if head_path is None and paths else head_path)
    return WatchGroupState(
        group_id=f"group-{name}",
        directory=str(tmp_path.resolve()),
        logical_name=name,
        split_family="7z",
        head_path=str(Path(selected_head).resolve()) if selected_head else "",
        input_paths=normalized,
        owned_paths=normalized,
        status=status,
    )


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


def test_completed_work_is_not_retained_as_processed_history(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))

    state.record_attempt(str(archive), stat.st_size, stat.st_mtime, "device:inode")
    assert state.pending_work
    state.complete_work([str(archive)])

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert not WatchStateStore(str(state_path)).pending_work_items()
    assert "snapshots" not in payload
    assert "pending_work" in payload


def test_pending_work_survives_restart_until_completed(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))
    state.record_attempt(str(archive), stat.st_size, stat.st_mtime, "device:inode")

    reloaded = WatchStateStore(str(state_path))
    assert [item.path for item in reloaded.pending_work_items()] == [str(archive.resolve())]

    reloaded.complete_work([str(archive)])
    assert not WatchStateStore(str(state_path)).pending_work_items()


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


def test_metadata_observation_advances_retry_entry_without_changing_failure(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    state = WatchStateStore(str(state_path))
    state.mark(
        str(archive),
        archive.stat().st_size,
        100.0,
        file_id="file",
        change_usn=10,
        status="failed_password",
        error="password",
        failure_payload={"kind": "wrong_password", "blockers": ["password"]},
    )
    candidate = type("Candidate", (), {
        "path": str(archive),
        "size": archive.stat().st_size,
        "mtime": 50.0,
        "file_id": "file",
        "change_usn": 11,
    })()

    assert state.advance_entry_observation(candidate)

    entry = WatchStateStore(str(state_path)).latest_entry_for_path(str(archive))
    assert entry is not None
    assert entry.mtime == 50.0
    assert entry.change_usn == 11
    assert entry.status == "failed_password"
    assert entry.last_error == "password"
    assert entry.attempt_count == 1


def test_previous_state_schema_is_intentionally_not_loaded(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"version": 5, "entries": {"legacy": {"status": "done"}}}), encoding="utf-8")

    state = WatchStateStore(str(state_path))

    assert not state.pending_work
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["version"] == watch_state_module.STATE_VERSION
    assert "snapshots" not in payload


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

    [pending] = WatchStateStore(str(state_path)).pending_work_items()
    assert pending.path == str(archive.resolve())
    assert pending.force is True


def test_prune_missing_records_removes_stale_entries_and_groups(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    present = tmp_path / "present.zip"
    partial_present = tmp_path / "partial.7z.001"
    missing = tmp_path / "missing.zip"
    present.write_bytes(b"present")
    partial_present.write_bytes(b"partial")

    state.mark(
        str(present),
        present.stat().st_size,
        present.stat().st_mtime,
        status="failed_password",
        failure_payload={"blockers": ["password"]},
    )
    state.mark(
        str(missing),
        1,
        1.0,
        status="failed_password",
        failure_payload={"blockers": ["password"]},
    )
    state.groups["present"] = _group_state(tmp_path, "present", [present])
    state.groups["missing"] = _group_state(tmp_path, "missing", [missing])
    state.groups["partial"] = _group_state(tmp_path, "partial", [partial_present, missing])

    removed_entries, removed_groups = state.prune_missing_records()

    assert (removed_entries, removed_groups) == (1, 2)
    assert state.latest_entry_for_path(str(present)) is not None
    assert state.latest_entry_for_path(str(missing)) is None
    assert set(state.groups) == {"present"}


def test_prune_missing_records_keeps_group_with_missing_expected_volume(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    first = tmp_path / "split.7z.001"
    third = tmp_path / "split.7z.003"
    first.write_bytes(b"first")
    third.write_bytes(b"third")
    group = _group_state(tmp_path, "split", [first, third], status="waiting")
    group.missing_indices = [2]
    state.groups[group.group_id] = group
    missing_head_member = tmp_path / "head-missing.7z.002"
    missing_head_member.write_bytes(b"member")
    missing_head_group = _group_state(
        tmp_path,
        "head-missing",
        [missing_head_member],
        head_path="",
        status="waiting",
    )
    missing_head_group.missing_indices = [1]
    state.groups[missing_head_group.group_id] = missing_head_group

    removed_entries, removed_groups = state.prune_missing_records()

    assert (removed_entries, removed_groups) == (0, 0)
    assert state.group_state(group.group_id) is not None
    assert state.group_state(missing_head_group.group_id) is not None


def test_prune_missing_records_retains_records_when_presence_is_unknown(tmp_path, monkeypatch):
    state = WatchStateStore(str(tmp_path / "state.json"))
    archive = tmp_path / "protected.zip"
    archive.write_bytes(b"archive")
    state.mark(
        str(archive),
        archive.stat().st_size,
        archive.stat().st_mtime,
        status="failed_password",
        failure_payload={"blockers": ["password"]},
    )
    original_stat = watch_state_module.os.stat

    def blocked_stat(path, *args, **kwargs):
        if str(path).casefold() == str(archive).casefold():
            raise PermissionError("temporary access failure")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(watch_state_module.os, "stat", blocked_stat)

    assert state.prune_missing_records() == (0, 0)
    assert state.latest_entry_for_path(str(archive)) is not None
