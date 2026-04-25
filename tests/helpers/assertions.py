import json
from collections.abc import Mapping, Sequence
from typing import Any


MISSING = object()


def get_path(payload: Any, path: str) -> Any:
    current = payload
    parts = path.split(".")
    index = 0
    while index < len(parts):
        part = parts[index]
        if isinstance(current, Mapping):
            matched = False
            for end in range(len(parts), index, -1):
                candidate = ".".join(parts[index:end])
                if candidate in current:
                    current = current[candidate]
                    index = end
                    matched = True
                    break
            if matched:
                continue
            return MISSING
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
            if not part.isdigit():
                return MISSING
            sequence_index = int(part)
            current = current[sequence_index] if 0 <= sequence_index < len(current) else MISSING
            index += 1
        else:
            return MISSING
        if current is MISSING:
            return MISSING
    return current


def assert_case_expectations(payload: dict[str, Any], expectations: dict[str, Any]):
    for path, expected in expectations.items():
        actual = get_path(payload, path)
        assert actual is not MISSING, f"Missing assertion path: {path}\nPayload:\n{json.dumps(payload, indent=2, ensure_ascii=False, default=str)}"
        assert actual == expected, f"{path}: expected {expected!r}, got {actual!r}"
