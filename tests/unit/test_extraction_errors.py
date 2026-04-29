import json
import subprocess

from packrelic.coordinator.repair_loop import terminal_failure_reason
from packrelic.extraction.internal.workflow.errors import classify_extract_error
from packrelic.extraction.result import ExtractionResult


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


def _worker_completed(payload: dict) -> subprocess.CompletedProcess:
    event = {"type": "result", **payload}
    return subprocess.CompletedProcess(
        args=["sevenzip_worker"],
        returncode=1,
        stdout=json.dumps(event),
        stderr="",
    )
