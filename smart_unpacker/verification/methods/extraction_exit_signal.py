from smart_unpacker.verification.evidence import VerificationEvidence
from smart_unpacker.verification.registry import register_verification_method
from smart_unpacker.verification.result import VerificationIssue, VerificationStepResult


@register_verification_method("extraction_exit_signal")
class ExtractionExitSignalMethod:
    name = "extraction_exit_signal"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        result = evidence.extraction_result
        if not result.success:
            return VerificationStepResult(
                method=self.name,
                status="failed",
                score_delta=-abs(int(config.get("failure_penalty", 100) or 100)),
                hard_fail=bool(config.get("hard_fail_on_extract_failure", True)),
                issues=[
                    VerificationIssue(
                        method=self.name,
                        code="fail.extraction_failed",
                        message=result.error or "Extraction result is not successful",
                        path=result.archive or evidence.archive_path,
                    )
                ],
            )

        issues: list[VerificationIssue] = []
        score_delta = 0
        if result.error:
            score_delta -= abs(int(config.get("success_with_error_penalty", 10) or 10))
            issues.append(VerificationIssue(
                method=self.name,
                code="warning.success_with_error",
                message=result.error,
                path=result.archive or evidence.archive_path,
            ))

        return VerificationStepResult(
            method=self.name,
            status="warning" if issues else "passed",
            score_delta=score_delta,
            issues=issues,
        )
