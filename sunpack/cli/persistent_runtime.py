from __future__ import annotations

from contextlib import asynccontextmanager
import copy
import json
from typing import AsyncIterator

from sunpack.config.loader import config_cache_token
from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.coordinator.engine import PipelineEngine
from sunpack.cli.runtime_state import server_runtime_active, set_server_runtime_active
from sunpack.detection.options import DetectionOptions


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
_ENGINES: dict[tuple[tuple[object, ...], str, bool], PipelineEngine] = {}
_LATEST_IDLE_SECONDS: float | None = None


def enable_persistent_runtime() -> None:
    set_server_runtime_active(True)


async def close_persistent_runtime() -> None:
    global _LATEST_IDLE_SECONDS
    engines = tuple(_ENGINES.values())
    _ENGINES.clear()
    _LATEST_IDLE_SECONDS = None
    set_server_runtime_active(False)
    for engine in engines:
        await engine.aclose(graceful=True)


def persistent_runtime_is_idle() -> bool:
    return all(engine.is_idle() for engine in _ENGINES.values())


def persistent_server_idle_seconds() -> float:
    default = advanced_config_value(("performance", "persistent_server_idle_seconds"))
    if _LATEST_IDLE_SECONDS is not None:
        return _LATEST_IDLE_SECONDS
    engine = next(iter(_ENGINES.values()), None)
    config = engine.config if engine is not None else {}
    performance = config.get("performance") if isinstance(config.get("performance"), dict) else {}
    try:
        return max(0.0, float(performance.get("persistent_server_idle_seconds", default)))
    except (TypeError, ValueError):
        return max(0.0, float(default))


@asynccontextmanager
async def pipeline_engine(
    config: dict,
    detection_options: DetectionOptions | None = None,
) -> AsyncIterator[PipelineEngine]:
    if not server_runtime_active():
        raise RuntimeError("extract pipeline is only available inside the persistent server")

    global _LATEST_IDLE_SECONDS
    options = detection_options or DetectionOptions()
    performance = config.get("performance") if isinstance(config.get("performance"), dict) else {}
    try:
        _LATEST_IDLE_SECONDS = max(
            0.0,
            float(performance.get("persistent_server_idle_seconds", persistent_server_idle_seconds())),
        )
    except (TypeError, ValueError):
        pass
    key = (config_cache_token(), _stable_config_key(config), options.deep_scan)
    engine = _ENGINES.get(key)
    if engine is None:
        engine_config = copy.deepcopy(config)
        created = (
            PipelineEngine(engine_config, detection_options=options)
            if options.deep_scan
            else PipelineEngine(engine_config)
        )
        engine = await created.__aenter__()
        _ENGINES[key] = engine
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
