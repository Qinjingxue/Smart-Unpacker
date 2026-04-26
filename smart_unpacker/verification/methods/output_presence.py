from smart_unpacker.verification.evidence import VerificationEvidence
from smart_unpacker.verification.methods._output_stats import collect_output_stats
from smart_unpacker.verification.registry import register_verification_method
from smart_unpacker.verification.result import VerificationIssue, VerificationStepResult


@register_verification_method("output_presence")
class OutputPresenceMethod:
    name = "output_presence"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        stats = collect_output_stats(evidence.output_dir)
        issues: list[VerificationIssue] = []
        score_delta = 0
        hard_fail = False

        if not stats.exists:
            return self._fail(
                code="fail.output_missing",
                message="Extraction output directory does not exist",
                path=evidence.output_dir,
                penalty=config.get("missing_penalty", 100),
                hard_fail=config.get("hard_fail_on_missing", True),
            )
        if not stats.is_dir:
            return self._fail(
                code="fail.output_not_directory",
                message="Extraction output path is not a directory",
                path=evidence.output_dir,
                penalty=config.get("not_directory_penalty", 100),
                hard_fail=config.get("hard_fail_on_not_directory", True),
            )
        if stats.file_count <= 0:
            return self._fail(
                code="fail.output_empty",
                message="Extraction output contains no files",
                path=evidence.output_dir,
                penalty=config.get("empty_penalty", 80),
                hard_fail=config.get("hard_fail_on_empty", True),
            )

        if stats.unreadable_count:
            score_delta -= abs(int(config.get("unreadable_penalty", 30) or 30))
            issues.append(VerificationIssue(
                method=self.name,
                code="fail.output_unreadable_files",
                message="Some output files could not be inspected",
                path=evidence.output_dir,
                expected=0,
                actual=stats.unreadable_count,
            ))

        if stats.transient_file_count and stats.transient_file_count == stats.file_count:
            score_delta -= abs(int(config.get("only_transient_penalty", 60) or 60))
            hard_fail = bool(config.get("hard_fail_on_only_transient", False))
            issues.append(VerificationIssue(
                method=self.name,
                code="fail.output_only_transient_files",
                message="Extraction output only contains transient-looking files",
                path=evidence.output_dir,
                expected=0,
                actual=stats.transient_file_count,
            ))
        elif stats.transient_file_count:
            score_delta -= abs(int(config.get("transient_penalty", 10) or 10))
            issues.append(VerificationIssue(
                method=self.name,
                code="warning.output_transient_files",
                message="Extraction output contains transient-looking files",
                path=evidence.output_dir,
                expected=0,
                actual=stats.transient_file_count,
            ))

        return VerificationStepResult(
            method=self.name,
            status="warning" if issues and not hard_fail else "failed" if hard_fail else "passed",
            score_delta=score_delta,
            issues=issues,
            hard_fail=hard_fail,
        )

    def _fail(self, code: str, message: str, path: str, penalty, hard_fail) -> VerificationStepResult:
        return VerificationStepResult(
            method=self.name,
            status="failed",
            score_delta=-abs(int(penalty or 0)),
            hard_fail=bool(hard_fail),
            issues=[
                VerificationIssue(
                    method=self.name,
                    code=code,
                    message=message,
                    path=path,
                )
            ],
        )
