import os

from sunpack.filesystem.watcher.state import WatchStateStore


def test_done_entry_is_retried_when_generated_output_was_deleted(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    output = tmp_path / "sample"
    archive.write_bytes(b"archive")
    output.mkdir()
    stat = archive.stat()
    state = WatchStateStore(str(state_path))
    state.mark(
        str(archive),
        stat.st_size,
        stat.st_mtime,
        sample_digest="digest",
        status="done",
        output_dir=str(output),
        generated_output_dirs=[str(output)],
    )

    assert state.should_skip(str(archive), stat.st_size, stat.st_mtime, "digest")

    output.rmdir()

    assert not state.should_skip(str(archive), stat.st_size, stat.st_mtime, "digest")
    reloaded = WatchStateStore(str(state_path))
    assert os.path.normcase(str(archive.resolve())) in reloaded.invalidated_paths
    assert not reloaded.should_skip(str(archive), stat.st_size, stat.st_mtime, "digest")


def test_successful_retry_clears_persisted_path_invalidation(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    output = tmp_path / "sample"
    archive.write_bytes(b"archive")
    output.mkdir()
    stat = archive.stat()
    state = WatchStateStore(str(state_path))
    state.mark(
        str(archive),
        stat.st_size,
        stat.st_mtime,
        sample_digest="digest",
        status="done",
        output_dir=str(output),
    )
    state.invalidate_path(str(archive))

    state.mark(
        str(archive),
        stat.st_size,
        stat.st_mtime,
        sample_digest="digest",
        status="done",
        output_dir=str(output),
    )

    assert not state.invalidated_paths
    assert state.should_skip(str(archive), stat.st_size, stat.st_mtime, "digest")


def test_deleting_a_file_inside_tracked_output_invalidates_source_archive(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    output = tmp_path / "sample"
    extracted_file = output / "payload.txt"
    archive.write_bytes(b"archive")
    output.mkdir()
    extracted_file.write_text("payload", encoding="utf-8")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))
    state.mark(
        str(archive),
        stat.st_size,
        stat.st_mtime,
        sample_digest="digest",
        status="done",
        output_dir=str(output),
    )

    extracted_file.unlink()
    assert state.invalidate_path(str(extracted_file))

    assert not state.should_skip(str(archive), stat.st_size, stat.st_mtime, "digest")


def test_missing_predicted_output_at_completion_is_not_tracked(tmp_path):
    state_path = tmp_path / "state.json"
    archive = tmp_path / "sample.zip"
    flattened_intermediate = tmp_path / "sample" / "removed-child"
    archive.write_bytes(b"archive")
    stat = archive.stat()
    state = WatchStateStore(str(state_path))
    state.mark(
        str(archive),
        stat.st_size,
        stat.st_mtime,
        sample_digest="digest",
        status="done",
        output_dir=str(flattened_intermediate),
    )

    entry = state.latest_entry_for_path(str(archive))
    assert entry is not None
    assert entry.output_tracking_initialized
    assert entry.tracked_output_dirs == []
    assert state.should_skip(str(archive), stat.st_size, stat.st_mtime, "digest")
