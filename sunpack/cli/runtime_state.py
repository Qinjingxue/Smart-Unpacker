from __future__ import annotations

import threading


_LOCK = threading.Lock()
_ACTIVE = False


def set_server_runtime_active(active: bool) -> None:
    global _ACTIVE
    with _LOCK:
        _ACTIVE = bool(active)


def server_runtime_active() -> bool:
    with _LOCK:
        return _ACTIVE
