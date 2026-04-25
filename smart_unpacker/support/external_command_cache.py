import copy
import json
import os
import subprocess
import threading
from collections import OrderedDict
from collections.abc import Callable, Sequence
from typing import Any


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
    norm_path = os.path.normcase(os.path.normpath(path or ""))
    try:
        stat = os.stat(norm_path)
    except OSError:
        return norm_path, 0, 0
    return norm_path, stat.st_size, stat.st_mtime_ns


def directory_identity(path: str) -> tuple[str, int, tuple]:
    norm_path = os.path.normcase(os.path.normpath(path or ""))
    try:
        entries = []
        for entry in os.scandir(norm_path):
            try:
                stat = entry.stat()
                entries.append((entry.name.lower(), entry.is_dir(), stat.st_size, stat.st_mtime_ns))
            except OSError:
                entries.append((entry.name.lower(), entry.is_dir(), 0, 0))
        return norm_path, len(entries), tuple(sorted(entries))
    except OSError:
        return norm_path, 0, ()


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
