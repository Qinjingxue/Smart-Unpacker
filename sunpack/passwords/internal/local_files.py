from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sunpack.passwords.internal.lists import dedupe_passwords, read_password_file


DIRECTORY_PASSWORD_CONTEXT_FACT = "passwords.directory_context"
DIRECTORY_PASSWORD_FILE_NAME = ".sunpack-passwords.txt"
DEFAULT_MAX_PASSWORD_FILE_BYTES = 1024 * 1024
DEFAULT_MAX_PASSWORD_LENGTH = 512


def discover_directory_passwords_for_archive(archive_path: str, config: dict | None = None) -> list[str]:
    directory = os.path.dirname(os.path.abspath(archive_path or ""))
    if not directory or not os.path.isdir(directory):
        return []
    password_config = _password_config(config)
    if password_config.get("directory_passwords_enabled") is False:
        return []
    max_bytes = _positive_int(password_config.get("directory_passwords_max_file_bytes"), DEFAULT_MAX_PASSWORD_FILE_BYTES)
    max_password_length = _positive_int(password_config.get("directory_passwords_max_password_length"), DEFAULT_MAX_PASSWORD_LENGTH)

    path = Path(directory) / DIRECTORY_PASSWORD_FILE_NAME

    passwords: list[str] = []
    if _is_readable_password_file(path, max_bytes=max_bytes):
        try:
            passwords.extend(_plausible_passwords(read_password_file(str(path)), max_password_length=max_password_length))
        except Exception:
            pass
    return dedupe_passwords(passwords)


def is_directory_password_file(path: str, config: dict | None = None) -> bool:
    if not path:
        return False
    password_config = _password_config(config)
    if password_config.get("directory_passwords_enabled") is False:
        return False
    return Path(path).name == DIRECTORY_PASSWORD_FILE_NAME


def directory_password_context_from_task(task: Any) -> list[str]:
    fact_bag = getattr(task, "fact_bag", None)
    if fact_bag is None:
        return []
    values = fact_bag.get(DIRECTORY_PASSWORD_CONTEXT_FACT)
    if not isinstance(values, list):
        return []
    return [str(value) for value in values if isinstance(value, str)]


def _password_config(config: dict | None) -> dict:
    if not isinstance(config, dict):
        return {}
    password_config = config.get("passwords")
    return dict(password_config) if isinstance(password_config, dict) else {}


def _is_readable_password_file(path: Path, *, max_bytes: int) -> bool:
    try:
        if not path.is_file():
            return False
        return path.stat().st_size <= max_bytes
    except OSError:
        return False


def _plausible_passwords(passwords: list[str], *, max_password_length: int) -> list[str]:
    result = []
    for password in passwords:
        if not password or len(password) > max_password_length:
            continue
        if any(ord(ch) < 32 and ch != "\t" for ch in password):
            continue
        result.append(password)
    return result


def _positive_int(value: object, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default
