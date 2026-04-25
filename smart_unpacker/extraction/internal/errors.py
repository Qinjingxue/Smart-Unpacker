import os
import subprocess
from typing import Optional


def _norm(err_text: str) -> str:
    return (err_text or "").lower()


def has_definite_wrong_password(err_text: str) -> bool:
    err_lower = (err_text or "").lower()
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
            "is not archive",
            "archive is corrupted",
            "checksum error",
            "unsupported compression method",
            "unsupported method",
        )
    )


def classify_extract_error(
    run_result: Optional[subprocess.CompletedProcess],
    err_text: str,
    archive: str = None,
    is_split_archive: bool = False,
) -> str:
    error_msg = "未知原因"
    archive_name = os.path.basename(archive or "").lower()
    is_split_archive = is_split_archive or _looks_like_split_archive_name(archive_name)
    err_lower = _norm(err_text)

    if "missing volume" in err_lower:
        return "分卷缺失或不完整"
    if "unexpected end of archive" in err_lower or "unexpected end of data" in err_lower:
        return "分卷缺失或不完整" if is_split_archive else "压缩包损坏"
    if "crc failed" in err_lower or "data error in encrypted file" in err_lower:
        if is_split_archive:
            return "压缩包损坏"
        if has_definite_wrong_password(err_lower):
            return "密码错误"
        return "压缩包损坏"
    if "headers error" in err_lower or "data error" in err_lower:
        return "压缩包损坏"
    if "cannot open the file as" in err_lower or "can not open the file as archive" in err_lower:
        return "分卷缺失或不完整" if is_split_archive else "压缩包损坏"
    if "is not archive" in err_lower or "archive is corrupted" in err_lower or "checksum error" in err_lower:
        return "压缩包损坏"
    if "unsupported compression method" in err_lower or "unsupported method" in err_lower:
        return "致命错误 (文件损坏或格式不支持)"
    if has_definite_wrong_password(err_lower) or "cannot open encrypted archive" in err_lower:
        return "密码错误"

    if run_result:
        code = run_result.returncode
        if code == 1:
            error_msg = "警告 (文件被占用或部分失败)"
        elif code == 2:
            error_msg = "致命错误 (文件损坏或格式不支持)"
        elif code == 7:
            error_msg = "命令行参数错误"
        elif code == 8:
            error_msg = "内存/磁盘空间不足"
        elif code == 255:
            error_msg = "用户中断"

    return error_msg


def _looks_like_split_archive_name(archive_name: str) -> bool:
    if not archive_name:
        return False
    import re

    return bool(
        re.search(r"\.part\d+\.rar(?:\.[^.]+)?$", archive_name, re.IGNORECASE)
        or re.search(r"\.(7z|zip|rar)\.\d{3}(?:\.[^.]+)?$", archive_name, re.IGNORECASE)
        or re.search(r"\.\d{3}(?:\.[^.]+)?$", archive_name, re.IGNORECASE)
    )
