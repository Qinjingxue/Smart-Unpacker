import json
import subprocess

from sunpack.coordinator.repair_loop import terminal_failure_reason
from sunpack.extraction.internal.workflow.errors import classify_extract_error
from sunpack.contracts.extraction import ExtractionResult


def test_split_worker_damage_takes_precedence_over_wrong_password_signal():
    completed = _worker_completed({
        "wrong_password": True,
        "damaged": True,
        "checksum_error": True,
        "missing_volume": False,
        "native_status": "wrong_password",
        "failure_kind": "checksum_error",
    })

    error = classify_extract_error(
        completed,
        "",
        archive="payload.7z.001",
        is_split_archive=True,
    )

    assert error == "压缩包损坏"


def test_split_payload_damage_is_not_terminal_wrong_password():
    result = ExtractionResult(
        success=False,
        archive="payload.7z.001",
        out_dir="out",
        all_parts=["payload.7z.001", "payload.7z.002"],
        error="密码错误",
        diagnostics={
            "result": {
                "wrong_password": True,
                "damaged": True,
                "checksum_error": True,
                "failure_kind": "checksum_error",
            },
        },
    )

    assert terminal_failure_reason(result) == ""


def test_plain_wrong_password_stays_terminal_for_split_archive():
    result = ExtractionResult(
        success=False,
        archive="payload.7z.001",
        out_dir="out",
        all_parts=["payload.7z.001", "payload.7z.002"],
        error="密码错误",
        diagnostics={
            "result": {
                "wrong_password": True,
                "damaged": False,
                "checksum_error": False,
            },
        },
    )

    assert terminal_failure_reason(result) == "wrong_password"


def test_worker_failure_kind_classifies_wrong_password_without_boolean_flag():
    completed = _worker_completed({
        "wrong_password": False,
        "native_status": "error",
        "failure_kind": "encrypted_or_wrong_password",
        "operation_result_name": "data_error",
        "message": "archive could not be extracted",
    })

    assert classify_extract_error(completed, "") == "密码错误"


def test_nested_worker_operation_result_classifies_wrong_password():
    completed = _worker_completed({
        "wrong_password": False,
        "native_status": "error",
        "diagnostics": {
            "failure_kind": "unknown",
            "operation_result_name": "wrong_password",
        },
    })

    assert classify_extract_error(completed, "") == "密码错误"


def _worker_completed(payload: dict) -> subprocess.CompletedProcess:
    event = {"type": "result", **payload}
    return subprocess.CompletedProcess(
        args=["sevenzip_worker"],
        returncode=1,
        stdout=json.dumps(event),
        stderr="",
    )
