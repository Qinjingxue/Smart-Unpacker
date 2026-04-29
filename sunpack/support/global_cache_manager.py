import copy
import json
import os
import subprocess
import threading
from collections import OrderedDict
from collections.abc import Callable, Sequence
from typing import Any

from sunpack_native import batch_file_head_facts as _native_batch_file_head_facts
from sunpack_native import scan_directory_entries as _native_scan_directory_entries

from sunpack.support.path_keys import path_key


DEFAULT_CACHE_CAPACITY = 512


class CacheManager:
    def __init__(self, default_capacity: int = DEFAULT_CACHE_CAPACITY):
        self.default_capacity = max(1, default_capacity)
        self._caches: dict[str, OrderedDict[tuple, Any]] = {}
        self._capacities: dict[str, int] = {}
        self._lock = threading.Lock()

    def get(self, namespace: str, key: tuple):
        with self._lock:
            cache = self._caches.get(namespace)
            if not cache or key not in cache:
                return None
            value = cache[key]
            cache.move_to_end(key)
            return copy.deepcopy(value)

    def set(self, namespace: str, key: tuple, value: Any):
        with self._lock:
            cache = self._caches.setdefault(namespace, OrderedDict())
            cache[key] = copy.deepcopy(value)
            cache.move_to_end(key)
            capacity = self._capacities.get(namespace, self.default_capacity)
            while len(cache) > capacity:
                cache.popitem(last=False)

    def cached(self, namespace: str, key: tuple, factory: Callable[[], Any]):
        cached = self.get(namespace, key)
        if cached is not None:
            return cached
        value = factory()
        self.set(namespace, key, value)
        return value

    def clear_namespace(self, namespace: str):
        with self._lock:
            self._caches.pop(namespace, None)

    def clear_all(self):
        with self._lock:
            self._caches.clear()


GLOBAL_CACHE = CacheManager()


def file_identity(path: str) -> tuple[str, int, int]:
    norm_path = path_key(path)
    rows = _native_batch_file_head_facts([norm_path], 0)
    if not rows or not isinstance(rows[0], dict):
        return norm_path, 0, 0
    return norm_path, int(rows[0].get("size") or 0), int(rows[0].get("mtime_ns") or 0)


def directory_identity(path: str) -> tuple[str, int, tuple]:
    norm_path = path_key(path)
    rows = _native_scan_directory_entries(norm_path, 0, [], [], [], None)
    if not rows:
        return norm_path, 0, ()
    entries = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("path"):
            continue
        name = os.path.basename(str(row.get("path") or "")).lower()
        entries.append((name, bool(row.get("is_dir")), int(row.get("size") or 0), int(row.get("mtime_ns") or 0)))
    return norm_path, len(entries), tuple(sorted(entries))


def stable_fingerprint(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    except TypeError:
        return repr(value)


def cached_value(namespace: str, key: tuple, factory: Callable[[], Any]):
    return GLOBAL_CACHE.cached(namespace, key, factory)


def cached_readonly_command(
    cmd: Sequence[str],
    file_path: str,
    runner: Callable[..., subprocess.CompletedProcess],
    **kwargs,
) -> subprocess.CompletedProcess:
    key = (tuple(str(part) for part in cmd), file_identity(file_path))
    cached = GLOBAL_CACHE.get("external_command", key)
    if cached is not None:
        return subprocess.CompletedProcess(
            args=list(cached.args) if isinstance(cached.args, list) else cached.args,
            returncode=cached.returncode,
            stdout=cached.stdout,
            stderr=cached.stderr,
        )

    result = runner(cmd, **kwargs)
    result_args = getattr(result, "args", list(cmd))
    stored = subprocess.CompletedProcess(
        args=list(result_args) if isinstance(result_args, list) else result_args,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )
    GLOBAL_CACHE.set("external_command", key, stored)
    return result


def clear_cache_namespace(namespace: str):
    GLOBAL_CACHE.clear_namespace(namespace)


def clear_all_caches():
    GLOBAL_CACHE.clear_all()
