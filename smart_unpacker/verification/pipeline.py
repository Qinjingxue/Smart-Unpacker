from smart_unpacker.verification.evidence import VerificationEvidence
from smart_unpacker.verification.registry import get_verification_method
from smart_unpacker.verification.result import VerificationIssue, VerificationResult


class VerificationPipeline:
    def __init__(self, config: dict):
        self.config = dict(config or {})
        self.initial_score = int(self.config.get("initial_score", 100))
        self.pass_threshold = int(self.config.get("pass_threshold", 70))
        self.fail_fast_threshold = int(self.config.get("fail_fast_threshold", 40))
        self.methods = list(self.config.get("methods") or [])

    def run(self, evidence: VerificationEvidence) -> VerificationResult:
        score = self.initial_score
        issues: list[VerificationIssue] = []
        methods_run: list[str] = []

        if not self.methods:
            return VerificationResult(
                ok=True,
                status="skipped",
                score=score,
                pass_threshold=self.pass_threshold,
                fail_fast_threshold=self.fail_fast_threshold,
            )

        for method_config in self.methods:
            if not isinstance(method_config, dict) or not method_config.get("enabled", True):
                continue
            method_name = str(method_config.get("name") or "").strip()
            if not method_name:
                continue
            method = get_verification_method(method_name)
            if method is None:
                issues.append(VerificationIssue(
                    method=method_name,
                    code="warning.unknown_method",
                    message=f"Unknown verification method: {method_name}",
                ))
                continue

            step = method.verify(evidence, method_config)
            score += int(step.score_delta or 0)
            methods_run.append(step.method or method_name)
            issues.extend(step.issues)

            if step.hard_fail:
                return self._failed(score, methods_run, issues, status="failed")
            if score < self.fail_fast_threshold:
                return self._failed(score, methods_run, issues, status="failed_fast")

        if score >= self.pass_threshold:
            return VerificationResult(
                ok=True,
                status="passed",
                score=score,
                pass_threshold=self.pass_threshold,
                fail_fast_threshold=self.fail_fast_threshold,
                methods_run=methods_run,
                issues=issues,
            )
        return self._failed(score, methods_run, issues, status="failed")

    def _failed(
        self,
        score: int,
        methods_run: list[str],
        issues: list[VerificationIssue],
        status: str,
    ) -> VerificationResult:
        return VerificationResult(
            ok=False,
            status=status,
            score=score,
            pass_threshold=self.pass_threshold,
            fail_fast_threshold=self.fail_fast_threshold,
            methods_run=methods_run,
            issues=issues,
        )

