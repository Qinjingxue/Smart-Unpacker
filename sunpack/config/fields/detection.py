from typing import Any

from sunpack.config.schema import ConfigField


def normalize_detection_enabled(value: Any) -> bool:
    return bool(value)


CONFIG_FIELDS = (
    ConfigField(
        path=("detection", "enabled"),
        default=True,
        normalize=normalize_detection_enabled,
        owner=__name__,
    ),
)
