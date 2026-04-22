from __future__ import annotations


MAGICS = {
    b"7z\xbc\xaf'\x1c": ".7z",
    b"Rar!": ".rar",
    b"PK\x03\x04": ".zip",
    b"PK\x05\x06": ".zip",
    b"PK\x07\x08": ".zip",
    b"\x1f\x8b": ".gz",
    b"BZh": ".bz2",
    b"\xfd7zXZ\x00": ".xz",
}

WEAK_MAGICS = {
    b"MZ": ".exe",
}

TAIL_MAGICS = {
    b"7z\xbc\xaf'\x1c": ".7z",
    b"Rar!": ".rar",
    b"PK\x03\x04": ".zip",
    b"PK\x05\x06": ".zip",
    b"PK\x07\x08": ".zip",
}
