from __future__ import annotations

from pathlib import Path


def marker_was_extracted(root: Path, marker_name: str, marker_text: str) -> bool:
    """Return whether a file whose text equals the marker was produced under root."""
    for path in root.rglob(marker_name):
        try:
            if path.read_text(encoding="utf-8") == marker_text:
                return True
        except OSError:
            continue
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            if path.read_text(encoding="utf-8") == marker_text:
                return True
        except (OSError, UnicodeDecodeError):
            continue
    return False
