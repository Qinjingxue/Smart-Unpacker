from types import SimpleNamespace

import pytest

from sunpack.contracts.detection import FactBag
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.result import ExtractionResult
from sunpack.passwords.candidates import PasswordCandidatePipeline
from sunpack.passwords.job import PasswordJob
from sunpack.passwords.scheduler import PasswordScheduler, PasswordSearchStatus
from sunpack.passwords.verifier import PasswordBatchVerification
from sunpack.passwords.verifier.base import normalize_verifier_status
from sunpack.passwords.verifier.sevenzip_dll import SevenZipDllVerifier
from sunpack.support.sevenzip_bridge import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_DAMAGED,
    STATUS_UNSUPPORTED,
    STATUS_WRONG_PASSWORD,
)
from sunpack.verification import VerificationScheduler
from sunpack.verification.result import DECISION_REQUEST_PASSWORD, SOURCE_INTEGRITY_UNKNOWN


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("no_match", "no_match"),
        ("unknown_need_fallback", "unknown_needs_final_verifier"),
        ("unknown_needs_fallback", "unknown_needs_final_verifier"),
        ("unsupported", "unsupported_method"),
        ("unexpected_backend_value", "unknown_needs_final_verifier"),
    ],
)
def test_verifier_statuses_are_normalized_at_adapter_boundary(raw, expected):
    assert normalize_verifier_status(raw) == expected


def test_scheduler_uses_no_match_status_not_backend_message(tmp_path):
    archive = tmp_path / "sample.rar"
    archive.write_bytes(b"rar")
    scheduler = PasswordScheduler(_StaticVerifier(PasswordBatchVerification(
        ok=False,
        status="no_match",
        attempts=2,
        error_text="rar5 password check did not match",
    )))

    result = scheduler.run(PasswordJob(
        archive_path=str(archive),
        candidates=PasswordCandidatePipeline.from_values(["bad-1", "bad-2"]),
    ))

    assert result.status == PasswordSearchStatus.EXHAUSTED
    assert result.password is None


@pytest.mark.parametrize(
    ("native_status", "expected"),
    [
        (STATUS_WRONG_PASSWORD, "no_match"),
        (STATUS_DAMAGED, "damaged"),
        (STATUS_UNSUPPORTED, "unsupported_method"),
        (STATUS_BACKEND_UNAVAILABLE, "backend_unavailable"),
    ],
)
def test_dll_verifier_preserves_native_failure_status(native_status, expected):
    native = _NativeTester(native_status)
    result = SevenZipDllVerifier(native_password_tester=native).verify_batch("sample.7z", ["bad"])

    assert result.status == expected


def test_embedded_failure_retains_nested_password_cause():
    password = FailureInfo(
        kind=FailureKind.WRONG_PASSWORD,
        stage="password_resolution",
        message="password rejected",
        user_action="request_password",
    )
    embedded = FailureInfo(
        kind=FailureKind.EMBEDDED_SEGMENTS_FAILED,
        stage="embedded_segments",
        message="segment failed",
        causes=(password,),
    )

    restored = FailureInfo.from_dict(embedded.to_dict())

    assert restored is not None
    assert restored.is_password_failure
    assert restored.contains(FailureKind.WRONG_PASSWORD)


def test_password_failure_bypasses_repair_verification(tmp_path):
    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(b"encrypted")
    failure = FailureInfo(
        kind=FailureKind.PASSWORD_REQUIRED,
        stage="password_resolution",
        message="password required",
        user_action="request_password",
    )
    result = ExtractionResult(
        success=False,
        archive=str(archive),
        out_dir=str(tmp_path / "out"),
        all_parts=[str(archive)],
        error=failure.message,
        failure=failure,
    )

    verification = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [{"name": "extraction_exit_signal"}],
        }
    }).verify(_task(archive), result)

    assert verification.decision_hint == DECISION_REQUEST_PASSWORD
    assert verification.source_integrity == SOURCE_INTEGRITY_UNKNOWN
    assert verification.failures[0].code == "fail.password_required"


class _StaticVerifier:
    def __init__(self, result):
        self.result = result

    def verify_batch(self, archive_path, passwords, *, part_paths=None, archive_input=None):
        return self.result


class _NativeTester:
    def __init__(self, status):
        self.status = status

    def try_passwords(self, archive_path, passwords, *, part_paths=None, archive_input=None):
        return SimpleNamespace(
            status=self.status,
            ok=False,
            matched_index=-1,
            attempts=len(passwords),
            message="native diagnostic",
        )


def _task(path) -> ArchiveTask:
    return ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        key=str(path),
        main_path=str(path),
        all_parts=[str(path)],
        decision="archive",
    )
