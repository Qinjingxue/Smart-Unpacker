from __future__ import annotations

from contextlib import contextmanager
import copy
import json
import threading
from typing import Iterator

from sunpack.config.loader import config_cache_token
from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.coordinator.engine import PipelineEngine


_MUTABLE_PATHS = {
    ("user_passwords",),
    ("builtin_passwords",),
    ("cli", "quiet"),
    ("cli", "verbose"),
    ("extraction", "quiet"),
    ("output", "root"),
    ("output", "common_root"),
    ("performance", "persistent_server_idle_seconds"),
}
_LOCK = threading.RLock()
_ENABLED = False
_ENGINE: PipelineEngine | None = None
_ENGINE_KEY: tuple[tuple[object, ...], str] | None = None


def enable_persistent_runtime() -> None:
    global _ENABLED
    with _LOCK:
        _ENABLED = True


def server_runtime_active() -> bool:
    with _LOCK:
        return _ENABLED


def close_persistent_runtime() -> None:
    global _ENABLED, _ENGINE, _ENGINE_KEY
    with _LOCK:
        engine = _ENGINE
        _ENGINE = None
        _ENGINE_KEY = None
        _ENABLED = False
    if engine is not None:
        engine.close(graceful=True)


def persistent_runtime_is_idle() -> bool:
    with _LOCK:
        engine = _ENGINE
    return engine is None or engine.is_idle()


def persistent_server_idle_seconds() -> float:
    default = advanced_config_value(("performance", "persistent_server_idle_seconds"))
    with _LOCK:
        engine = _ENGINE
        config = engine.config if engine is not None else {}
    performance = config.get("performance") if isinstance(config.get("performance"), dict) else {}
    try:
        return max(0.0, float(performance.get("persistent_server_idle_seconds", default)))
    except (TypeError, ValueError):
        return max(0.0, float(default))


@contextmanager
def pipeline_engine(config: dict) -> Iterator[PipelineEngine]:
    global _ENGINE, _ENGINE_KEY
    with _LOCK:
        enabled = _ENABLED
    if not enabled:
        raise RuntimeError("extract pipeline is only available inside the persistent server")

    key = (config_cache_token(), _stable_config_key(config))
    with _LOCK:
        if _ENGINE is None or _ENGINE_KEY != key:
            previous = _ENGINE
            _ENGINE = None
            _ENGINE_KEY = None
            if previous is not None:
                previous.close(graceful=True)
            _ENGINE = PipelineEngine(copy.deepcopy(config)).start()
            _ENGINE_KEY = key
        else:
            _ENGINE.reconfigure_request(config)
        engine = _ENGINE
    assert engine is not None
    yield engine


def _stable_config_key(config: dict) -> str:
    stable = copy.deepcopy(config)
    for path in _MUTABLE_PATHS:
        current = stable
        for key in path[:-1]:
            value = current.get(key)
            if not isinstance(value, dict):
                current = None
                break
            current = value
        if current is not None:
            current.pop(path[-1], None)
    return json.dumps(stable, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
