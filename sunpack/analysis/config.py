from typing import Any

from sunpack.config.advanced_defaults import advanced_config_value


DEFAULT_ANALYSIS_CONFIG = advanced_config_value(("analysis",))


def analysis_config(config: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict((config or {}).get("analysis") or {})
    return _merge(DEFAULT_ANALYSIS_CONFIG, payload)


def enabled_fuzzy_module_configs(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    fuzzy = config.get("fuzzy") if isinstance(config.get("fuzzy"), dict) else {}
    modules = fuzzy.get("modules")
    if not isinstance(modules, list):
        return {}
    result = {}
    for item in modules:
        if not isinstance(item, dict) or not item.get("enabled", False):
            continue
        name = item.get("name")
        if isinstance(name, str) and name.strip():
            result[name.strip()] = {key: value for key, value in item.items() if key not in {"name", "enabled"}}
    return result


def _merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result
