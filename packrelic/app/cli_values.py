import argparse

from packrelic.config.schema import normalize_config_value


def parse_non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def parse_bool_value(value: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on", "启用", "是"}:
        return True
    if normalized in {"0", "false", "no", "n", "off", "禁用", "否"}:
        return False
    raise argparse.ArgumentTypeError("must be true/false, yes/no, or 1/0")


def parse_recursive_extract_value(value: str):
    try:
        normalize_config_value(("recursive_extract",), value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return str(value).strip()


def parse_archive_cleanup_value(value: str) -> str:
    raw = str(value).strip().lower()
    try:
        normalize_config_value(("post_extract", "archive_cleanup_mode"), raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return raw
