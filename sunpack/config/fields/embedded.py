from typing import Any

from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.config.schema import ConfigField


DEFAULT_EMBEDDED_SCAN = advanced_config_value(("embedded_scan",))


def normalize_embedded_scan(value: Any) -> dict[str, bool]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("embedded_scan must be an object")
    unknown = set(value) - {"enabled"}
    if unknown:
        raise ValueError(f"embedded_scan has unknown fields: {', '.join(sorted(unknown))}")
    enabled = value.get("enabled", DEFAULT_EMBEDDED_SCAN["enabled"])
    if not isinstance(enabled, bool):
        raise ValueError("embedded_scan.enabled must be boolean")
    return {"enabled": enabled}


CONFIG_FIELDS = (
    ConfigField(
        path=("embedded_scan",),
        default=DEFAULT_EMBEDDED_SCAN,
        normalize=normalize_embedded_scan,
        owner=__name__,
    ),
)
