"""Coordinated clearing of process-wide runtime caches.

This module deliberately sits above the individual cache owners.  Native
reader resources remain owned by ``sunpack_native``; Python caches are cleared
through their public owner APIs.  The coordinator is only intended for an
idle process or engine.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sunpack.passwords.relation_prober import (
    clear_relation_probe_cache,
    relation_probe_cache_stats,
)
from sunpack.support.archive_knowledge_projection import (
    clear_projection_cache,
    projection_cache_stats,
)
from sunpack.support.archive_sessions import clear_archive_sessions
from sunpack.support.global_cache_manager import (
    clear_all_caches,
    global_cache_stats,
)


def runtime_cache_stats(*, inspection_services: Iterable[Any] = ()) -> dict[str, Any]:
    """Return lightweight counts for every cache owned by this coordinator."""

    result: dict[str, Any] = {
        "global_cache": global_cache_stats(),
        "projection_cache": projection_cache_stats(),
        "relation_probe_cache": relation_probe_cache_stats(),
        "archive_sessions": _archive_session_stats(),
        "reader": _reader_stats(),
        "native_seven_zip": _native_seven_zip_stats(),
        "watch_filesystem": _watch_filesystem_stats(),
        "inspection": [],
    }
    for service in inspection_services:
        cache = getattr(service, "cache", None)
        if cache is None:
            result["inspection"].append({"available": False})
            continue
        try:
            with cache._lock:
                result["inspection"].append({
                    "entries": len(cache._items),
                    "max_entries": int(cache.max_entries),
                })
        except (AttributeError, TypeError, ValueError):
            result["inspection"].append({"available": False})
    return result


def clear_all_runtime_caches(*, inspection_services: Iterable[Any] = ()) -> dict[str, Any]:
    """Clear process-wide memoized data and return a per-owner report.

    The caller must establish that no pipeline request or completion callback
    is active.  The function does not stop worker pools, clear watch state, or
    invalidate request-local objects that are still referenced by a caller.
    """

    report: dict[str, Any] = {"errors": []}
    for name, action in (
        ("inspection", lambda: _clear_inspection_caches(inspection_services)),
        ("relation_probe_cache", clear_relation_probe_cache),
        ("projection_cache", clear_projection_cache),
        ("global_cache", clear_all_caches),
        ("native_seven_zip", _clear_native_seven_zip_caches),
        ("watch_filesystem", _clear_watch_filesystem_resources),
        ("archive_sessions", clear_archive_sessions),
    ):
        try:
            report[name] = action()
        except Exception as exc:  # pragma: no cover - defensive process cleanup
            report["errors"].append({
                "component": name,
                "error": str(exc),
                "error_type": type(exc).__name__,
            })
    return report


def _clear_inspection_caches(services: Iterable[Any]) -> list[dict[str, Any]]:
    result = []
    for service in services:
        clear = getattr(service, "clear_cache", None)
        if not callable(clear):
            result.append({"available": False})
            continue
        before = _inspection_entry_count(service)
        clear()
        result.append({"entries": before})
    return result


def _inspection_entry_count(service: Any) -> int:
    cache = getattr(service, "cache", None)
    if cache is None:
        return 0
    with cache._lock:
        return len(cache._items)


def _archive_session_stats() -> dict[str, int]:
    from sunpack.support import archive_sessions

    with archive_sessions._LOCK:
        return {"sessions": len(archive_sessions._SESSIONS)}


def _reader_stats() -> dict[str, Any]:
    try:
        from sunpack_native import reader_cache_stats

        return dict(reader_cache_stats())
    except (ImportError, AttributeError, TypeError):
        return {"available": False}


def _native_seven_zip_stats() -> dict[str, Any]:
    try:
        from sunpack_native import seven_zip_runtime_cache_stats

        return dict(seven_zip_runtime_cache_stats())
    except (ImportError, AttributeError, TypeError):
        return {"available": False}


def _clear_native_seven_zip_caches() -> dict[str, Any]:
    try:
        from sunpack_native import clear_seven_zip_runtime_caches
    except (ImportError, AttributeError):
        return {"available": False}
    return dict(clear_seven_zip_runtime_caches())


def _watch_filesystem_stats() -> dict[str, Any]:
    try:
        from sunpack_native import watch_filesystem_resource_stats

        return dict(watch_filesystem_resource_stats())
    except (ImportError, AttributeError, TypeError):
        return {"available": False}


def _clear_watch_filesystem_resources() -> dict[str, Any]:
    try:
        from sunpack_native import clear_watch_filesystem_resources
    except (ImportError, AttributeError):
        return {"available": False}
    return {"volume_contexts": int(clear_watch_filesystem_resources())}
