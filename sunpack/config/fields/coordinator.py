from typing import Any

from sunpack.config.schema import ConfigField


def normalize_recursive_extract(value: Any) -> dict[str, Any]:
    raw = str(value).strip().lower()
    if raw == "*":
        return {"mode": "infinite", "max_rounds": 999}
    if raw == "?":
        return {"mode": "prompt", "max_rounds": 999}
    try:
        rounds = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError('recursive_extract must be "*", "?", or a positive integer') from exc
    if rounds <= 0:
        raise ValueError('recursive_extract must be "*", "?", or a positive integer')
    return {"mode": "fixed", "max_rounds": rounds}


DEFAULT_PIPELINE_CONFIG = {
    "batch_window_seconds": 0.0,
    "max_batch_requests": 64,
    "queue_capacity": 4096,
}


def normalize_pipeline_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("pipeline must be an object")
    config = {**DEFAULT_PIPELINE_CONFIG, **value}
    try:
        config["batch_window_seconds"] = max(0.0, float(config["batch_window_seconds"]))
        config["max_batch_requests"] = max(1, int(config["max_batch_requests"]))
        config["queue_capacity"] = max(1, int(config["queue_capacity"]))
    except (TypeError, ValueError) as exc:
        raise ValueError("pipeline batching fields must be numeric") from exc
    return config


CONFIG_FIELDS = (
    ConfigField(
        path=("recursive_extract",),
        default="1",
        normalize=normalize_recursive_extract,
        owner=__name__,
    ),
    ConfigField(
        path=("pipeline",),
        default=DEFAULT_PIPELINE_CONFIG,
        normalize=normalize_pipeline_config,
        owner=__name__,
    ),
)
