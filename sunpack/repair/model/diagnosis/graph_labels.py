from __future__ import annotations

import re
from typing import Any


def normalize_label_token(value: str) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def safe_node_token(value: Any) -> str:
    text = str(value if value is not None else "").strip().lower()
    text = text.replace("\\", "/")
    text = re.sub(r"[^a-z0-9_.:/-]+", "_", text)
    text = text.replace(":", "_").replace("/", "_")
    return text.strip("._-")[:160] or "item"


def label_zone(label: str) -> str:
    text = normalize_label_token(label)
    if text.startswith("zone:"):
        return text.split(":", 1)[1]
    if text.startswith("field:"):
        field = text.split(":", 1)[1]
        return field.split(".", 1)[0]
    return ""


def field_from_label(label: str) -> str:
    text = normalize_label_token(label)
    return text.split(":", 1)[1] if text.startswith("field:") else ""
