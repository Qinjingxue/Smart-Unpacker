from __future__ import annotations

from typing import Any


def normalize_format_name(value: Any) -> str:
    text = str(value or "").strip().lower().lstrip(".").replace("-", "_")
    return {
        "7zip": "7z",
        "seven_zip": "7z",
        "gz": "gzip",
        "bz2": "bzip2",
    }.get(text, text)
