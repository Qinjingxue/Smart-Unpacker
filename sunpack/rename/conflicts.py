import os
from collections.abc import MutableSet

from sunpack.support.path_keys import absolute_path_key


def next_available_path(path: str, reserved: MutableSet[str] | None = None) -> str:
    """Return path or the first browser-style numbered alternative."""
    candidate = os.path.normpath(path)
    parent = os.path.dirname(candidate)
    filename = os.path.basename(candidate)
    stem, extension = os.path.splitext(filename)
    index = 1
    while os.path.exists(candidate) or (reserved is not None and absolute_path_key(candidate) in reserved):
        candidate = os.path.join(parent, f"{stem}({index}){extension}")
        index += 1
    if reserved is not None:
        reserved.add(absolute_path_key(candidate))
    return candidate
