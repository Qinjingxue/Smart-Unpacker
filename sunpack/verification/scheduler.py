from typing import Any

from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.result import ExtractionResult
from sunpack.passwords import PasswordSession
from sunpack.verification.evidence import build_verification_evidence
from sunpack.verification.pipeline import VerificationPipeline
from sunpack.verification.result import (
    ASSESSMENT_DISABLED,
    DECISION_ACCEPT,
    DECISION_REPAIR,
    SOURCE_INTEGRITY_DAMAGED,
    SOURCE_INTEGRITY_UNKNOWN,
    VerificationResult,
)


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
                    repair_hints=dict(evidence.repair_hints),
                )
            return VerificationResult(
                completeness=1.0,
                recoverable_upper_bound=1.0,
                assessment_status=ASSESSMENT_DISABLED,
                source_integrity=SOURCE_INTEGRITY_UNKNOWN,
                decision_hint=DECISION_ACCEPT,
                repair_hints=dict(evidence.repair_hints),
            )
        return VerificationPipeline(self.config).run(evidence)

    def _verification_config(self, config: dict[str, Any]) -> dict:
        if "verification" in config and isinstance(config.get("verification"), dict):
            return dict(config["verification"])
        return dict(config or {})
