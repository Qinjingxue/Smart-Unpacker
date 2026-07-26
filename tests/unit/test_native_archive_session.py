from __future__ import annotations

import os

import pytest

from sunpack.support.archive_sessions import (
    clear_archive_sessions,
    get_archive_session,
    release_archive_sessions_under,
)
from sunpack_native import NativeArchiveSession, reader_cache_stats


@pytest.fixture(autouse=True)
def _clear_python_sessions():
    clear_archive_sessions()
    yield
    clear_archive_sessions()


def test_python_lifecycle_reuses_session_and_invalidates_changed_file(tmp_path):
    path = tmp_path / "lifecycle.bin"
    path.write_bytes(b"abcdefgh")

    first = get_archive_session(os.fspath(path))
    assert get_archive_session(os.fspath(path)) is first
    assert bytes(first.read_at(2, 4)) == b"cdef"

    path.write_bytes(b"new-content")
    second = get_archive_session(os.fspath(path))
    assert second is not first
    assert bytes(second.read_at(0, 11)) == b"new-content"


def test_rust_manager_reuses_blocks_and_handle_across_python_calls(tmp_path):
    path = tmp_path / "shared-cache.bin"
    path.write_bytes(bytes(range(256)) * 1024)

    before = dict(reader_cache_stats())
    first = NativeArchiveSession(os.fspath(path))
    assert bytes(first.read_at(17, 128)) == path.read_bytes()[17:145]
    after_first = dict(reader_cache_stats())
    del first

    second = NativeArchiveSession(os.fspath(path))
    assert bytes(second.read_at(17, 128)) == path.read_bytes()[17:145]
    after_second = dict(reader_cache_stats())

    assert after_first["physical_bytes"] > before["physical_bytes"]
    assert after_second["physical_bytes"] == after_first["physical_bytes"]
    assert after_second["cache_hits"] > after_first["cache_hits"]
    assert after_second["handle_hits"] > after_first["handle_hits"]
    assert after_second["cache_shards"] == 64


def test_clear_archive_sessions_releases_native_blocks_and_handles(tmp_path):
    path = tmp_path / "request-cache.bin"
    path.write_bytes(bytes(range(256)) * 1024)
    session = get_archive_session(os.fspath(path))
    assert bytes(session.read_at(17, 128)) == path.read_bytes()[17:145]
    del session
    populated = dict(reader_cache_stats())
    assert populated["open_handles"] >= 1
    assert populated["cache_entries"] >= 1
    assert populated["hot_cache_bytes"] + populated["general_cache_bytes"] > 0

    clear_archive_sessions()

    cleared = dict(reader_cache_stats())
    assert cleared["open_handles"] == 0
    assert cleared["cache_entries"] == 0
    assert cleared["hot_cache_bytes"] == 0
    assert cleared["general_cache_bytes"] == 0


def test_session_analysis_view_preserves_cache_budget_and_eof_semantics(tmp_path):
    path = tmp_path / "analysis-view.bin"
    path.write_bytes(b"abcdefgh")
    session = get_archive_session(os.fspath(path))
    view = session.analysis_view(cache_bytes=8, max_read_bytes=4, max_concurrent_reads=1)

    assert bytes(view.read_at(0, 4)) == b"abcd"
    assert bytes(view.read_at(0, 4)) == b"abcd"
    stats = dict(view.stats())
    assert stats == {"read_bytes": 4, "cache_hits": 1}
    with pytest.raises(RuntimeError, match="read budget exceeded"):
        view.read_at(4, 1)

    eof_view = session.analysis_view(cache_bytes=0)
    assert bytes(eof_view.read_at(6, 8)) == b"gh"


def test_release_boundary_allows_windows_pipeline_directory_promotion(tmp_path):
    source = tmp_path / "work"
    target = tmp_path / "promoted"
    source.mkdir()
    path = source / "payload.bin"
    path.write_bytes(b"payload")
    assert bytes(get_archive_session(os.fspath(path)).read_at(0, 7)) == b"payload"

    release_archive_sessions_under(os.fspath(source))
    os.replace(source, target)
    assert (target / "payload.bin").read_bytes() == b"payload"
