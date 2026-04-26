from smart_unpacker.verification.evidence import VerificationEvidence
from smart_unpacker.verification.methods._output_stats import output_stats_for_evidence
from smart_unpacker.verification.registry import register_verification_method
from smart_unpacker.verification.result import VerificationIssue, VerificationStepResult


@register_verification_method("manifest_size_match")
class ManifestSizeMatchMethod:
    name = "manifest_size_match"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        expected_files = _as_int(evidence.analysis.get("file_count"))
        expected_size = _as_int(evidence.analysis.get("total_unpacked_size"))
        if expected_files <= 0 and expected_size <= 0:
            return VerificationStepResult(method=self.name, status="skipped")

        stats = output_stats_for_evidence(evidence)
        if not stats.exists or not stats.is_dir:
            return VerificationStepResult(method=self.name, status="skipped")

        issues: list[VerificationIssue] = []
        score_delta = 0
        hard_fail = False

        if expected_files > 0:
            file_tolerance = max(
                int(config.get("file_count_abs_tolerance", 2) or 0),
                int(expected_files * float(config.get("file_count_ratio_tolerance", 0.05) or 0.0)),
            )
            lower_bound = max(0, expected_files - file_tolerance)
            upper_bound = expected_files + file_tolerance
            if stats.file_count < lower_bound:
                score_delta -= abs(int(config.get("file_count_under_penalty", 60) or 60))
                hard_fail = hard_fail or bool(config.get("hard_fail_on_large_file_count_under", False))
                issues.append(VerificationIssue(
                    method=self.name,
                    code="fail.manifest_file_count_under",
                    message="Output file count is lower than archive manifest file count",
                    path=evidence.output_dir,
                    expected=expected_files,
                    actual=stats.file_count,
                ))
            elif stats.file_count > upper_bound:
                score_delta -= abs(int(config.get("file_count_over_penalty", 15) or 15))
                issues.append(VerificationIssue(
                    method=self.name,
                    code="warning.manifest_file_count_over",
                    message="Output file count is higher than archive manifest file count",
                    path=evidence.output_dir,
                    expected=expected_files,
                    actual=stats.file_count,
                ))

        if expected_size > 0:
            size_tolerance = max(
                int(config.get("size_abs_tolerance_bytes", 1024 * 1024) or 0),
                int(expected_size * float(config.get("size_ratio_tolerance", 0.02) or 0.0)),
            )
            lower_bound = max(0, expected_size - size_tolerance)
            upper_bound = expected_size + size_tolerance
            if stats.total_size < lower_bound:
                score_delta -= abs(int(config.get("size_under_penalty", 60) or 60))
                hard_fail = hard_fail or bool(config.get("hard_fail_on_large_size_under", False))
                issues.append(VerificationIssue(
                    method=self.name,
                    code="fail.manifest_size_under",
                    message="Output total size is lower than archive manifest unpacked size",
                    path=evidence.output_dir,
                    expected=expected_size,
                    actual=stats.total_size,
                ))
            elif stats.total_size > upper_bound:
                score_delta -= abs(int(config.get("size_over_penalty", 25) or 25))
                issues.append(VerificationIssue(
                    method=self.name,
                    code="warning.manifest_size_over",
                    message="Output total size is higher than archive manifest unpacked size",
                    path=evidence.output_dir,
                    expected=expected_size,
                    actual=stats.total_size,
                ))

        if not issues:
            return VerificationStepResult(method=self.name, status="passed")
        return VerificationStepResult(
            method=self.name,
            status="failed" if hard_fail else "warning",
            score_delta=score_delta,
            issues=issues,
            hard_fail=hard_fail,
        )


def _as_int(value) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0
