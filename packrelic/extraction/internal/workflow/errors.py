import os
import subprocess
from typing import Optional

from packrelic.extraction.internal.sevenzip.worker_diagnostics import worker_result_payload
from packrelic.support.archive_error_signals import (
    has_archive_damage_signals,
    has_definite_wrong_password,
    has_transient_system_signals,
    looks_like_split_archive_name,
    normalize_error_text,
)

_norm = normalize_error_text


def should_retry_extract_failure(
    run_result: Optional[subprocess.CompletedProcess],
    err_text: str,
    archive: str = None,
    is_split_archive: bool = False,
) -> bool:
    err_lower = _norm(err_text)
    worker_result = worker_result_payload(run_result) or worker_result_payload(err_text)
    if worker_result:
        if worker_result.get("wrong_password") or worker_result.get("damaged") or worker_result.get("missing_volume"):
            return False
        if worker_result.get("native_status") in {"wrong_password", "damaged", "unsupported"}:
            return False

    if has_definite_wrong_password(err_lower):
        return False
    if has_archive_damage_signals(err_lower):
        return False

    if has_transient_system_signals(err_lower):
        return True

    if not run_result:
        return False

    code = run_result.returncode
    if code in (-100, -101, -102, 8):
        return True
    if code is not None and code < 0:
        return True

    return False


def classify_extract_error(
    run_result: Optional[subprocess.CompletedProcess],
    err_text: str,
    archive: str = None,
    is_split_archive: bool = False,
) -> str:
    error_msg = "未知原因"
    archive_name = os.path.basename(archive or "").lower()
    is_split_archive = is_split_archive or looks_like_split_archive_name(archive_name)
    err_lower = _norm(err_text)
    worker_result = worker_result_payload(run_result) or worker_result_payload(err_text)
    if worker_result:
        if worker_result.get("missing_volume"):
            return "分卷缺失或不完整"
        if is_split_archive and _worker_reports_payload_damage(worker_result):
            return "压缩包损坏"
        if worker_result.get("wrong_password") or worker_result.get("native_status") == "wrong_password":
            return "密码错误"
        if worker_result.get("checksum_error"):
            return "压缩包损坏"
        if worker_result.get("damaged") or worker_result.get("native_status") == "damaged":
            return "压缩包损坏"
        if worker_result.get("unsupported_method"):
            return "致命错误 (文件损坏或格式不支持)"
        if worker_result.get("native_status") == "backend_unavailable":
            return "7z后端不可用"
        if worker_result.get("native_status") == "unsupported":
            return "致命错误 (文件损坏或格式不支持)"

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
        if code == -100:
            return "7z进程启动失败"
        if code == -101:
            return "7z进程超时"
        if code == -102:
            return "7z进程无进展"
        if code is not None and code < 0:
            return "7z进程异常退出或被终止"
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
        elif code not in (None, 0):
            error_msg = f"7z进程异常退出 (退出码 {code})"

    return error_msg


def _worker_reports_payload_damage(worker_result: dict) -> bool:
    if worker_result.get("checksum_error") or worker_result.get("damaged"):
        return True
    if worker_result.get("native_status") == "damaged":
        return True
    failure_kind = str(worker_result.get("failure_kind") or "").lower()
    if failure_kind in {"corrupted_data", "data_error", "checksum_error", "crc_error"}:
        return True
    diagnostics = worker_result.get("diagnostics")
    if isinstance(diagnostics, dict):
        nested_kind = str(diagnostics.get("failure_kind") or "").lower()
        if nested_kind in {"corrupted_data", "data_error", "checksum_error", "crc_error"}:
            return True
    return False
