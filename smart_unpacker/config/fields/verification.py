from typing import Any

from smart_unpacker.config.schema import ConfigField


DEFAULT_VERIFICATION_CONFIG = {
    "enabled": False,
    "initial_score": 100,
    "pass_threshold": 70,
    "fail_fast_threshold": 40,
    "max_retries": 0,
    "cleanup_failed_output": True,
    "methods": [
        {"name": "extraction_exit_signal", "enabled": True},
        {"name": "output_presence", "enabled": True},
        {"name": "expected_name_presence", "enabled": True},
        {"name": "manifest_size_match", "enabled": True},
        {"name": "archive_test_crc", "enabled": True},
    ],
}


def normalize_verification_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("verification must be an object")
    config = dict(DEFAULT_VERIFICATION_CONFIG)
    config.update(value)
    config["enabled"] = bool(config.get("enabled", False))
    config["initial_score"] = _int_field(config, "initial_score")
    config["pass_threshold"] = _int_field(config, "pass_threshold")
    config["fail_fast_threshold"] = _int_field(config, "fail_fast_threshold")
    config["max_retries"] = max(0, _int_field(config, "max_retries"))
    config["cleanup_failed_output"] = bool(config.get("cleanup_failed_output", True))
    if config["fail_fast_threshold"] > config["pass_threshold"]:
        raise ValueError("verification.fail_fast_threshold must be <= verification.pass_threshold")
    config["methods"] = _normalize_methods(config.get("methods"))
    return config


def _int_field(config: dict[str, Any], name: str) -> int:
    try:
        return int(config.get(name))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"verification.{name} must be an integer") from exc


def _normalize_methods(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("verification.methods must be a list")
    methods = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"verification.methods[{index}] must be an object")
        name = str(item.get("name") or "").strip()
        if not name:
            raise ValueError(f"verification.methods[{index}].name must not be empty")
        normalized = dict(item)
        normalized["name"] = name
        normalized["enabled"] = bool(item.get("enabled", True))
        methods.append(normalized)
    return methods


CONFIG_FIELDS = (
    ConfigField(
        path=("verification",),
        default=DEFAULT_VERIFICATION_CONFIG,
        normalize=normalize_verification_config,
        owner=__name__,
    ),
)
