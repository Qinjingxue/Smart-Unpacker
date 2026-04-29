from __future__ import annotations

from typing import Any

from sunpack.support.global_cache_manager import file_identity
from sunpack.support.path_keys import path_key


def file_identity_for_context(context: Any, path: str) -> tuple[str, int, int]:
    key = path_key(path)
    fact_bag = getattr(context, "fact_bag", None)
    if fact_bag is not None and key == path_key(fact_bag.get("file.path") or ""):
        size = fact_bag.get("file.size")
        mtime_ns = fact_bag.get("file.mtime_ns")
        if isinstance(size, int) and isinstance(mtime_ns, int):
            return key, size, mtime_ns
    scan_session = getattr(context, "scan_session", None)
    if scan_session is not None:
        identity = scan_session.file_identity_for_path(path)
        if identity[1] or identity[2]:
            return identity
    return file_identity(path)
