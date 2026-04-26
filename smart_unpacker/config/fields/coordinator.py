from typing import Any

from smart_unpacker.config.schema import ConfigField


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


CONFIG_FIELDS = (
    ConfigField(
        path=("recursive_extract",),
        default="1",
        normalize=normalize_recursive_extract,
        owner=__name__,
    ),
)
