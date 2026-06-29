import json

from sunpack.filesystem.watcher.state import WatchStateStore


def test_input_snapshot_persists_and_matches_only_identical_stable_input(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))

    state.observe_and_queue(str(archive), stat.st_size, stat.st_mtime, "digest")
    state.complete_work([str(archive)])

    reloaded = WatchStateStore(str(state_path))
    assert reloaded.snapshot_matches(str(archive), stat.st_size, stat.st_mtime, "digest")
    assert not reloaded.snapshot_matches(str(archive), stat.st_size, stat.st_mtime, "different")
    assert not reloaded.pending_snapshots()


def test_departure_removes_snapshot_so_identical_input_is_new_again(tmp_path):
    state = WatchStateStore(str(tmp_path / "state.json"))
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state.observe_and_queue(str(archive), stat.st_size, stat.st_mtime, "digest")
    state.complete_work([str(archive)])

    assert state.forget_path(str(archive))
    assert not state.snapshot_matches(str(archive), stat.st_size, stat.st_mtime, "digest")


def test_pending_work_survives_restart_until_completed(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))
    state.observe_and_queue(str(archive), stat.st_size, stat.st_mtime, "digest")

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


def test_owned_output_roots_are_separate_from_input_snapshots(tmp_path):
    state_path = tmp_path / "state.json"
    output = tmp_path / "sample"
    state = WatchStateStore(str(state_path))
    state.remember_output_roots([str(output)])

    reloaded = WatchStateStore(str(state_path))
    assert reloaded.generated_output_roots() == [str(output.resolve())]
    assert not reloaded.entries
    assert not reloaded.snapshots


def test_previous_state_schema_is_intentionally_not_loaded(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"version": 5, "entries": {"legacy": {"status": "done"}}}), encoding="utf-8")

    state = WatchStateStore(str(state_path))

    assert not state.snapshots
    assert not state.entries
