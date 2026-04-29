from typing import Any

from packrelic.contracts.tasks import ArchiveTask
from packrelic.extraction.result import ExtractionResult
from packrelic.passwords import PasswordSession
from packrelic.verification.evidence import build_verification_evidence
from packrelic.verification.pipeline import VerificationPipeline
from packrelic.verification.result import (
    ASSESSMENT_DISABLED,
    DECISION_ACCEPT,
    DECISION_REPAIR,
    SOURCE_INTEGRITY_DAMAGED,
    SOURCE_INTEGRITY_UNKNOWN,
    VerificationResult,
)


DEFAULT_VERIFICATION_CONFIG = {
    "enabled": False,
    "max_retries": 0,
    "cleanup_failed_output": True,
    "accept_partial_when_source_damaged": True,
    "partial_min_completeness": 0.2,
    "complete_accept_threshold": 0.999,
    "partial_accept_threshold": 0.2,
    "retry_on_verification_failure": True,
    "methods": [
        {"name": "extraction_exit_signal", "enabled": True},
        {"name": "output_presence", "enabled": True},
        {"name": "expected_name_presence", "enabled": True},
        {"name": "manifest_size_match", "enabled": True},
        {"name": "archive_test_crc", "enabled": True},
        {"name": "sample_readability", "enabled": True},
    ],
}


class VerificationScheduler:
    def __init__(self, config: dict[str, Any] | None = None, password_session: PasswordSession | None = None):
        self.config = self._verification_config(config or {})
        self.password_session = password_session

    def verify(self, task: ArchiveTask, extraction_result: ExtractionResult) -> VerificationResult:
        evidence = build_verification_evidence(task, extraction_result, self.password_session)
        if not self.config.get("enabled", False):
            if not extraction_result.success:
                return VerificationResult(
                    completeness=0.0,
                    recoverable_upper_bound=1.0,
                    assessment_status=ASSESSMENT_DISABLED,
                    source_integrity=SOURCE_INTEGRITY_DAMAGED,
                    decision_hint=DECISION_REPAIR,
                )
            return VerificationResult(
                completeness=1.0,
                recoverable_upper_bound=1.0,
                assessment_status=ASSESSMENT_DISABLED,
                source_integrity=SOURCE_INTEGRITY_UNKNOWN,
                decision_hint=DECISION_ACCEPT,
            )
        return VerificationPipeline(self.config).run(evidence)

    def _verification_config(self, config: dict[str, Any]) -> dict:
        if "verification" in config and isinstance(config.get("verification"), dict):
            config = config["verification"]
        merged = dict(DEFAULT_VERIFICATION_CONFIG)
        merged.update(config or {})
        return merged
