from typing import Any

from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.config.schema import ConfigField


DEFAULT_EXTRACTION_CONFIG = advanced_config_value(("extraction",))


def normalize_extraction_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("extraction must be an object")
    config = dict(DEFAULT_EXTRACTION_CONFIG)
    config.update(value)
    config["write_progress_manifest"] = bool(config.get("write_progress_manifest", False))
    return config


CONFIG_FIELDS = (
    ConfigField(
        path=("extraction",),
        default=DEFAULT_EXTRACTION_CONFIG,
        normalize=normalize_extraction_config,
        owner=__name__,
    ),
)
