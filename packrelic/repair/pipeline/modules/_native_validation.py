from __future__ import annotations

from typing import Any

from packrelic.support.sevenzip_native import get_native_password_tester


def validate_with_native_probe(path: str, expected_format: str, config: dict[str, Any]) -> tuple[bool, list[str], dict[str, Any]]:
    deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
    if not bool(deep.get("verify_candidates", True)):
        return True, [], {"skipped": True, "reason": "repair.deep.verify_candidates is false"}

    try:
        tester = get_native_password_tester()
    except Exception as exc:
        return True, [f"native 7z probe unavailable: {exc}"], {"available": False, "error": str(exc)}
    if not tester.available():
        return True, ["native 7z probe unavailable"], {"available": False}

    try:
        probe = tester.probe_archive(path)
    except Exception as exc:
        return False, [f"native 7z probe failed: {exc}"], {"available": True, "error": str(exc)}

    expected = _native_format(expected_format)
    actual = _native_format(probe.archive_type)
    ok = bool(probe.is_archive) and not bool(probe.is_broken) and (not expected or actual == expected)
    details = {
        "available": True,
        "status": probe.status,
        "is_archive": probe.is_archive,
        "is_broken": probe.is_broken,
        "checksum_error": probe.checksum_error,
        "archive_type": probe.archive_type,
        "offset": probe.offset,
        "item_count": probe.item_count,
        "message": probe.message,
    }
    if ok:
        return True, [], details
    return False, [f"native 7z probe rejected candidate: {probe.message or probe.archive_type or probe.status}"], details


def _native_format(value: str) -> str:
    text = str(value or "").strip().lower().lstrip(".")
    if text in {"seven_zip", "sevenzip"}:
        return "7z"
    return text
