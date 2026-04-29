import os
from typing import Any


def normalize_ext(value: str) -> str:
    ext = str(value or "").strip().lower()
    if not ext:
        return ""
    return ext if ext.startswith(".") else f".{ext}"


def normalize_exts(values) -> set[str]:
    normalized = set()
    for value in values or []:
        if not isinstance(value, str) or not value.strip():
            continue
        normalized.add(normalize_ext(value))
    return normalized


def normalize_extension_score_groups(values) -> dict[str, int]:
    if not isinstance(values, list):
        return {}
    normalized = {}
    for group in values:
        if not isinstance(group, dict):
            continue
        try:
            score = int(group.get("score"))
        except (TypeError, ValueError):
            continue
        for ext in group.get("extensions") or []:
            if not isinstance(ext, str) or not ext.strip():
                continue
            normalized[normalize_ext(ext)] = score
    return normalized


def path_extension(path: Any) -> str:
    return os.path.splitext(str(path or ""))[1].lower()
