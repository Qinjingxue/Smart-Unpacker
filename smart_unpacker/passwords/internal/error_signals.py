def _norm(err_text: str) -> str:
    return (err_text or "").lower()


def has_definite_wrong_password(err_text: str) -> bool:
    err_lower = _norm(err_text)
    return (
        "cannot open encrypted archive. wrong password?" in err_lower
        or "error: wrong password :" in err_lower
        or "wrong password?" in err_lower
        or "wrong password" in err_lower
        or "enter password" in err_lower
        or "password is incorrect" in err_lower
        or "incorrect password" in err_lower
    )


def has_archive_damage_signals(err_text: str) -> bool:
    err_lower = _norm(err_text)
    return any(
        marker in err_lower
        for marker in (
            "unexpected end of archive",
            "unexpected end of data",
            "missing volume",
            "crc failed",
            "data error in encrypted file",
            "headers error",
            "data error",
            "can not open the file as archive",
            "cannot open the file as",
            "could not be opened by supported handlers",
            "is not archive",
            "archive is corrupted",
            "checksum error",
            "unsupported compression method",
            "unsupported method",
        )
    )
