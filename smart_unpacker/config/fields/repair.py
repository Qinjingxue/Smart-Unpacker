from typing import Any

from smart_unpacker.config.schema import ConfigField
from smart_unpacker.repair.config import DEFAULT_REPAIR_CONFIG, normalize_repair_config


def normalize_repair_field(value: Any) -> dict[str, Any]:
    return normalize_repair_config(value)


CONFIG_FIELDS = (
    ConfigField(
        path=("repair",),
        default=DEFAULT_REPAIR_CONFIG,
        normalize=normalize_repair_field,
        owner=__name__,
    ),
)
