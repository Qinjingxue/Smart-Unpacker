from typing import Any

from sunpack.config.schema import ConfigField


DEFAULT_WATCH_CONFIG = {
    "interval_seconds": 1.0,
    "cold_start_seconds": 1.0,
    "quiet_min_seconds": 2.5,
    "quiet_max_seconds": 180.0,
    "initial_scan": True,
    "max_folders": 16,
    "observer_stop_timeout_seconds": 5.0,
    "output_suppression_seconds": 120.0,
    "password_retry_debounce_seconds": 1.0,
    "password_retry_include_subtree": True,
    "clipboard_monitor_enabled": True,
    "clipboard_builtin_max_entries": 30,
    "enabled": False,
    "roots": [],
    "out_dir": ".",
    "tray_enabled": True,
    "state_dir": "",
    "reload_poll_seconds": 1.0,
}


def normalize_watch_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("watch must be an object")
    raw_config = dict(value)
    config = dict(DEFAULT_WATCH_CONFIG)
    config.update(raw_config)
    if "cold_start_seconds" not in raw_config and "quiet_seconds" in raw_config:
        config["cold_start_seconds"] = raw_config["quiet_seconds"]
    config.pop("quiet_seconds", None)
    config.pop("recursive", None)
    config["interval_seconds"] = max(0.1, _float_field(config, "interval_seconds"))
    config["cold_start_seconds"] = max(0.0, _float_field(config, "cold_start_seconds"))
    config["quiet_min_seconds"] = max(0.0, _float_field(config, "quiet_min_seconds"))
    config["quiet_max_seconds"] = max(
        config["cold_start_seconds"],
        config["quiet_min_seconds"],
        _float_field(config, "quiet_max_seconds"),
    )
    config["initial_scan"] = bool(config.get("initial_scan", True))
    config["max_folders"] = max(1, _int_field(config, "max_folders"))
    config["observer_stop_timeout_seconds"] = max(0.0, _float_field(config, "observer_stop_timeout_seconds"))
    config["output_suppression_seconds"] = max(0.0, _float_field(config, "output_suppression_seconds"))
    config["password_retry_debounce_seconds"] = max(0.0, _float_field(config, "password_retry_debounce_seconds"))
    config["password_retry_include_subtree"] = bool(config.get("password_retry_include_subtree", True))
    config["clipboard_monitor_enabled"] = bool(config.get("clipboard_monitor_enabled", True))
    config["clipboard_builtin_max_entries"] = max(1, _int_field(config, "clipboard_builtin_max_entries"))
    roots = config.get("roots", [])
    if roots is None:
        roots = []
    if not isinstance(roots, list):
        raise ValueError("watch.roots must be a list")
    config["roots"] = [str(item) for item in roots if str(item or "").strip()]
    config["enabled"] = bool(config.get("enabled", False))
    config["out_dir"] = str(config.get("out_dir") or ".")
    config["tray_enabled"] = bool(config.get("tray_enabled", True))
    config["state_dir"] = str(config.get("state_dir") or "")
    config["reload_poll_seconds"] = max(0.2, _float_field(config, "reload_poll_seconds"))
    return config


def _float_field(config: dict[str, Any], name: str) -> float:
    try:
        return float(config.get(name))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"watch.{name} must be a number") from exc


def _int_field(config: dict[str, Any], name: str) -> int:
    try:
        return int(config.get(name))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"watch.{name} must be an integer") from exc


CONFIG_FIELDS = (
    ConfigField(
        path=("watch",),
        default=DEFAULT_WATCH_CONFIG,
        normalize=normalize_watch_config,
        owner=__name__,
    ),
)
