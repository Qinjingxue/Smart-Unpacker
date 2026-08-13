import os


_LITE_VALUES = frozenset({"lite", "disabled", "off", "none"})


def is_lite_edition() -> bool:
    value = os.environ.get("SUNPACK_REPAIR_SYSTEM", "full").strip().lower()
    return value in _LITE_VALUES


def detection_scoring_enabled() -> bool:
    return not is_lite_edition()
