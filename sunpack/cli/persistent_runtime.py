from __future__ import annotations

from contextlib import asynccontextmanager
import copy
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, AsyncIterator

from sunpack.config.loader import config_source_key, load_config, load_effective_config_payload
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
ConfigSourceKey = tuple[str | None, str | None, str | None]


@dataclass(frozen=True)
class _ConfigSnapshot:
    source_key: ConfigSourceKey
    config_path: Path
    raw_payload: dict[str, Any]
    normalized_config: dict[str, Any]


_ENGINES: dict[tuple[ConfigSourceKey, str, bool], PipelineEngine] = {}
_CONFIG_SNAPSHOTS: dict[ConfigSourceKey, _ConfigSnapshot] = {}
_LATEST_IDLE_SECONDS: float | None = None


def enable_persistent_runtime() -> None:
    set_server_runtime_active(True)


async def close_persistent_runtime() -> None:
    global _LATEST_IDLE_SECONDS
    engines = tuple(_ENGINES.values())
    _ENGINES.clear()
    _CONFIG_SNAPSHOTS.clear()
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


def _snapshot_for(request_cwd: str | Path | None) -> _ConfigSnapshot:
    source_key = config_source_key(request_cwd)
    snapshot = _CONFIG_SNAPSHOTS.get(source_key)
    if snapshot is None:
        config_path, raw_payload = load_effective_config_payload(request_cwd)
        snapshot = _ConfigSnapshot(
            source_key=source_key,
            config_path=config_path,
            raw_payload=copy.deepcopy(raw_payload),
            normalized_config=copy.deepcopy(load_config(request_cwd)),
        )
        _CONFIG_SNAPSHOTS[source_key] = snapshot
    return snapshot


def load_request_config(request_cwd: str | Path | None = None) -> dict[str, Any]:
    """Load config for one CLI request, retaining persistent snapshots by source path."""
    if not server_runtime_active():
        return load_config(request_cwd)
    return copy.deepcopy(_snapshot_for(request_cwd).normalized_config)


def load_request_config_payload(request_cwd: str | Path | None = None) -> tuple[Path, dict[str, Any]]:
    """Return the external payload for a request without reloading an existing snapshot."""
    if not server_runtime_active():
        return load_effective_config_payload(request_cwd)
    snapshot = _snapshot_for(request_cwd)
    return snapshot.config_path, copy.deepcopy(snapshot.raw_payload)


def request_config_source_key(request_cwd: str | Path | None = None) -> ConfigSourceKey:
    return config_source_key(request_cwd)


@asynccontextmanager
async def pipeline_engine(
    config: dict,
    detection_options: DetectionOptions | None = None,
    *,
    source_key: ConfigSourceKey | None = None,
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
    key = (source_key or config_source_key(), _stable_config_key(config), options.deep_scan)
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
