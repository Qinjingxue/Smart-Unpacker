from __future__ import annotations

import copy
import json
from collections import OrderedDict, Counter
from pathlib import Path
from typing import Any, Callable

from sunpack.support.json_values import canonical_digest, stable_json_value


class RepairRuntimeCache:
    def __init__(self, *, enabled: bool = True, max_entries: int = 512) -> None:
        self.enabled = bool(enabled)
        self.max_entries = max(1, int(max_entries or 512))
        self._entries: OrderedDict[tuple[str, str], Any] = OrderedDict()
        self._hits: Counter[str] = Counter()
        self._misses: Counter[str] = Counter()

    def get_or_compute(self, namespace: str, key: Any, compute: Callable[[], Any]) -> Any:
        if not self.enabled:
            self._misses[namespace] += 1
            return compute()
        cache_key = (str(namespace), stable_cache_key(key))
        if cache_key in self._entries:
            value = self._entries.pop(cache_key)
            if _cached_value_still_valid(value):
                self._entries[cache_key] = value
                self._hits[namespace] += 1
                return copy.deepcopy(value)
            self._misses[namespace] += 1
        else:
            self._misses[namespace] += 1
        value = compute()
        self._entries[cache_key] = copy.deepcopy(value)
        self._entries.move_to_end(cache_key)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        return value

    def stats(self) -> dict[str, Any]:
        hits = dict(self._hits)
        misses = dict(self._misses)
        return {
            "enabled": self.enabled,
            "entries": len(self._entries),
            "max_entries": self.max_entries,
            "hits": sum(hits.values()),
            "misses": sum(misses.values()),
            "by_namespace": {
                namespace: {
                    "hits": int(hits.get(namespace, 0)),
                    "misses": int(misses.get(namespace, 0)),
                }
                for namespace in sorted(set(hits) | set(misses))
            },
        }


def stable_cache_key(payload: Any) -> str:
    return canonical_digest(payload, bytes_digest_key="bytes_sha256")




def _cached_value_still_valid(value: Any) -> bool:
    for path in _paths_in_value(value):
        if path and not Path(path).is_file():
            return False
    return True


def _paths_in_value(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"selected_path", "path"} and isinstance(item, str) and item:
                yield item
            elif key == "workspace_paths" and isinstance(item, list):
                for path in item:
                    if isinstance(path, str) and path:
                        yield path
            else:
                yield from _paths_in_value(item)
    elif isinstance(value, list):
        for item in value:
            yield from _paths_in_value(item)
