import ctypes

from sunpack.passwords.internal.lists import dedupe_passwords, parse_password_lines


CF_UNICODETEXT = 13
DEFAULT_MAX_CLIPBOARD_CHARS = 64 * 1024
DEFAULT_MAX_PASSWORD_LENGTH = 512


def read_clipboard_passwords(
    *,
    max_chars: int = DEFAULT_MAX_CLIPBOARD_CHARS,
    max_password_length: int = DEFAULT_MAX_PASSWORD_LENGTH,
) -> list[str]:
    """Best-effort text clipboard reader for password candidates."""
    text = _read_windows_unicode_clipboard(max_chars=max_chars)
    if not text:
        return []
    return dedupe_passwords(_plausible_passwords(parse_password_lines(text), max_password_length=max_password_length))


def _read_windows_unicode_clipboard(*, max_chars: int) -> str:
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        kernel32.GlobalSize.restype = ctypes.c_size_t
        kernel32.GlobalLock.restype = ctypes.c_void_p
    except Exception:
        return ""

    opened = False
    try:
        if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
            return ""
        if not user32.OpenClipboard(None):
            return ""
        opened = True
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return ""
        size_bytes = int(kernel32.GlobalSize(handle) or 0)
        if size_bytes <= 0 or size_bytes > max_chars * 2 + 2:
            return ""
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            return ""
        try:
            return ctypes.wstring_at(pointer, max_chars)
        finally:
            kernel32.GlobalUnlock(handle)
    except Exception:
        return ""
    finally:
        if opened:
            try:
                user32.CloseClipboard()
            except Exception:
                pass


def _plausible_passwords(passwords: list[str], *, max_password_length: int) -> list[str]:
    result = []
    for password in passwords:
        if not password or len(password) > max_password_length:
            continue
        if any(_is_disallowed_control(ch) for ch in password):
            continue
        result.append(password)
    return result


def _is_disallowed_control(ch: str) -> bool:
    code = ord(ch)
    return code < 32 and ch not in {"\t"}
