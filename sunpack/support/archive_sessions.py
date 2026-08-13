from __future__ import annotations

import os
import threading
from collections import OrderedDict

from sunpack_native import (
    NativeArchiveSession,
    clear_reader_resources,
    release_reader_handles_under,
)


_MAX_SESSIONS = 128
_LOCK = threading.Lock()
_SESSIONS: OrderedDict[tuple[str, int, int], NativeArchiveSession] = OrderedDict()


def _identity(path: str) -> tuple[str, int, int]:
    normalized = os.path.abspath(os.path.normpath(path))
    stat = os.stat(normalized)
    return normalized, int(stat.st_size), int(stat.st_mtime_ns)


def get_archive_session(path: str) -> NativeArchiveSession:
    key = _identity(path)
    with _LOCK:
        session = _SESSIONS.get(key)
        if session is not None:
            _SESSIONS.move_to_end(key)
            return session
    session = NativeArchiveSession(key[0])
    with _LOCK:
        existing = _SESSIONS.get(key)
        if existing is not None:
            _SESSIONS.move_to_end(key)
            return existing
        stale = [item for item in _SESSIONS if item[0] == key[0] and item != key]
        for item in stale:
            _SESSIONS.pop(item, None)
        _SESSIONS[key] = session
        while len(_SESSIONS) > _MAX_SESSIONS:
            _SESSIONS.popitem(last=False)
        return session


def retain_archive_sessions(paths) -> None:
    for path in dict.fromkeys(str(path) for path in paths if path):
        get_archive_session(path)


def clear_archive_sessions() -> dict:
    with _LOCK:
        sessions = len(_SESSIONS)
        _SESSIONS.clear()
    return {
        "sessions": sessions,
        "reader": dict(clear_reader_resources()),
    }


def release_archive_sessions_under(path: str) -> None:
    root = os.path.abspath(os.path.normpath(path))
    def is_under(candidate: str) -> bool:
        try:
            return os.path.commonpath((candidate, root)) == root
        except ValueError:
            return False

    with _LOCK:
        stale = [key for key in _SESSIONS if is_under(key[0])]
        for key in stale:
            _SESSIONS.pop(key, None)
    release_reader_handles_under(root)
