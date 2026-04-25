import argparse


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
    normalized = str(value).strip()
    if normalized == "*":
        return {"mode": "infinite", "max_rounds": 999}
    if normalized == "?":
        return {"mode": "prompt", "max_rounds": 999}
    if normalized.isdigit() and int(normalized) > 0:
        return {"mode": "fixed", "max_rounds": int(normalized)}
    raise argparse.ArgumentTypeError('must be a positive integer, "*" or "?"')
