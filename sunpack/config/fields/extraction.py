from typing import Any

from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.config.schema import ConfigField
from sunpack.contracts.content_recovery import CONTENT_REQUIREMENTS, CONTENT_REQUIREMENT_COMPLETE


DEFAULT_EXTRACTION_CONFIG = advanced_config_value(("extraction",))


def normalize_extraction_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("extraction must be an object")
    config = dict(DEFAULT_EXTRACTION_CONFIG)
    config.update(value)
    config["write_progress_manifest"] = bool(config.get("write_progress_manifest", False))
    requirement = str(config.get("content_requirement") or CONTENT_REQUIREMENT_COMPLETE).strip().lower()
    if requirement not in CONTENT_REQUIREMENTS:
        raise ValueError("extraction.content_requirement must be 'complete' or 'allow_partial'")
    config["content_requirement"] = requirement
    return config


def normalize_disk_space(value: Any) -> dict[str, int]:
    defaults = advanced_config_value(("performance", "disk_space"))
    if not isinstance(value, dict):
        raise ValueError("performance.disk_space must be an object")
    if set(value) - set(defaults):
        raise ValueError("Unknown performance.disk_space field")
    result = {**defaults, **value}
    for key, number in result.items():
        if isinstance(number, bool) or not isinstance(number, int) or number < (0 if key == "reserve_bytes" else 1):
            raise ValueError(f"performance.disk_space.{key} is out of range")
    if result["quantum_bytes"] > 64 << 20 or result["reserve_bytes"] > (1 << 63) - 1 or result["sample_ms"] > 60000:
        raise ValueError("performance.disk_space exceeds its allowed range")
    return result


CONFIG_FIELDS = (
    ConfigField(path=("performance", "disk_space"),
                default=advanced_config_value(("performance", "disk_space")),
                normalize=normalize_disk_space, owner=__name__),
    ConfigField(
        path=("extraction",),
        default=DEFAULT_EXTRACTION_CONFIG,
        normalize=normalize_extraction_config,
        owner=__name__,
    ),
)
