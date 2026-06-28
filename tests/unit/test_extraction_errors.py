import json
import subprocess

from sunpack.repair.loop import terminal_failure_reason
from sunpack.extraction.internal.workflow.errors import classify_extract_failure
from sunpack.contracts.extraction import ExtractionResult
from sunpack.contracts.failures import FailureKind


def test_split_worker_damage_takes_precedence_over_wrong_password_signal():
    completed = _worker_completed({
        "wrong_password": True,
        "damaged": True,
        "checksum_error": True,
        "missing_volume": False,
        "native_status": "wrong_password",
        "failure_kind": "checksum_error",
    })

    failure = classify_extract_failure(
        completed,
        "",
        archive="payload.7z.001",
        is_split_archive=True,
    )

    assert failure.message_key == "failure.damaged"


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

    assert classify_extract_failure(completed, "").message_key == "failure.wrong_password"


def test_nested_worker_operation_result_classifies_wrong_password():
    completed = _worker_completed({
        "wrong_password": False,
        "native_status": "error",
        "diagnostics": {
            "failure_kind": "unknown",
            "operation_result_name": "wrong_password",
        },
    })

    assert classify_extract_failure(completed, "").message_key == "failure.wrong_password"


def test_structured_missing_volume_keeps_callback_evidence():
    completed = _worker_completed({
        "missing_volume": True,
        "missing_volume_evidence": "open_volume_callback_not_found",
        "missing_volume_name": "payload.7z.003",
    })

    failure = classify_extract_failure(completed, "")

    assert failure.kind is FailureKind.MISSING_VOLUME
    assert failure.details == {
        "missing_volume_confirmed": True,
        "evidence": "open_volume_callback_not_found",
        "missing_volume_name": "payload.7z.003",
    }


def test_tail_size_suspicion_does_not_become_missing_volume():
    completed = _worker_completed({
        "damaged": True,
        "missing_volume": False,
        "missing_volume_suspected": True,
        "missing_volume_evidence": "tail_size_heuristic",
    })

    failure = classify_extract_failure(completed, "", archive="payload.7z.001")

    assert failure.kind is FailureKind.DAMAGED
    assert failure.details["missing_volume_confirmed"] is False
    assert failure.details["evidence"] == "tail_size_heuristic"


def test_tail_size_suspicion_does_not_override_explicit_wrong_password():
    completed = _worker_completed({
        "wrong_password": True,
        "missing_volume": False,
        "missing_volume_suspected": True,
        "missing_volume_evidence": "tail_size_heuristic",
    })

    failure = classify_extract_failure(completed, "", archive="payload.7z.001")

    assert failure.kind is FailureKind.WRONG_PASSWORD


def test_split_name_plus_unexpected_end_is_still_damage_without_hard_evidence():
    failure = classify_extract_failure(None, "Unexpected end of archive", archive="payload.7z.001")

    assert failure.kind is FailureKind.DAMAGED


def test_split_name_plus_cannot_open_is_still_damage_without_hard_evidence():
    failure = classify_extract_failure(None, "Can not open the file as archive", archive="payload.7z.001")

    assert failure.kind is FailureKind.DAMAGED


def test_archive_name_containing_missing_volume_is_not_explicit_backend_evidence():
    failure = classify_extract_failure(
        None,
        "Can not open the file as archive: missing volume sample.7z.001",
        archive="missing volume sample.7z.001",
    )

    assert failure.kind is FailureKind.DAMAGED


def test_explicit_backend_missing_volume_line_remains_missing_volume():
    failure = classify_extract_failure(None, "ERROR: Missing volume : payload.7z.003")

    assert failure.kind is FailureKind.MISSING_VOLUME


def _worker_completed(payload: dict) -> subprocess.CompletedProcess:
    event = {"type": "result", **payload}
    return subprocess.CompletedProcess(
        args=["sevenzip_worker"],
        returncode=1,
        stdout=json.dumps(event),
        stderr="",
    )
