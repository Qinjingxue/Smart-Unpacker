from typing import Any

from sunpack.config.schema import ConfigField


DEFAULT_PASSWORDS_CONFIG = {
    "clipboard_passwords_enabled": True,
}


def normalize_passwords_config(value: Any) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("passwords must be an object")
    config = dict(DEFAULT_PASSWORDS_CONFIG)
    config.update(value)
    config["clipboard_passwords_enabled"] = bool(config.get("clipboard_passwords_enabled", True))
    return config


CONFIG_FIELDS = (
    ConfigField(
        path=("passwords",),
        default=DEFAULT_PASSWORDS_CONFIG,
        normalize=normalize_passwords_config,
        owner=__name__,
    ),
)
