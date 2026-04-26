import os
import unicodedata
from typing import Any

from smart_unpacker.verification.evidence import VerificationEvidence
from smart_unpacker.verification.methods._output_stats import collect_output_stats
from smart_unpacker.verification.registry import register_verification_method
from smart_unpacker.verification.result import VerificationIssue, VerificationStepResult


NAME_FIELDS = (
    "expected_names",
    "manifest_names",
    "item_names",
    "file_names",
    "path_samples",
    "paths",
)


@register_verification_method("expected_name_presence")
class ExpectedNamePresenceMethod:
    name = "expected_name_presence"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        expected_names = self._expected_names(evidence, config)
        if not expected_names:
            return VerificationStepResult(method=self.name, status="skipped")

        stats = collect_output_stats(evidence.output_dir)
        if not stats.exists or not stats.is_dir or not stats.relative_paths:
            return VerificationStepResult(method=self.name, status="skipped")

        output_paths = {_normalize_path(path) for path in stats.relative_paths}
        output_basenames = {_normalize_name(os.path.basename(path)) for path in stats.relative_paths}
        missing = []
        for expected in expected_names:
            normalized_path = _normalize_path(expected)
            basename = _normalize_name(os.path.basename(normalized_path))
            if normalized_path in output_paths or basename in output_basenames:
                continue
            missing.append(expected)

        if not missing:
            return VerificationStepResult(method=self.name, status="passed")

        total = len(expected_names)
        matched = total - len(missing)
        missing_ratio = len(missing) / max(1, total)
        required_match_ratio = float(config.get("required_match_ratio", 0.8) or 0.0)
        actual_match_ratio = matched / max(1, total)
        if actual_match_ratio >= required_match_ratio:
            penalty = int(config.get("minor_missing_penalty", 10) or 10)
            code = "warning.expected_names_partially_missing"
        elif matched == 0:
            penalty = int(config.get("all_missing_penalty", 60) or 60)
            code = "fail.expected_names_all_missing"
        else:
            penalty = int(config.get("missing_penalty", 35) or 35)
            code = "fail.expected_names_missing"

        hard_fail = bool(config.get("hard_fail_on_all_missing", False) and matched == 0)
        issue = VerificationIssue(
            method=self.name,
            code=code,
            message="Expected archive item names were not found in extraction output",
            path=evidence.output_dir,
            expected=expected_names,
            actual={
                "matched": matched,
                "missing": missing,
                "missing_ratio": round(missing_ratio, 3),
            },
        )
        return VerificationStepResult(
            method=self.name,
            status="failed" if hard_fail else "warning",
            score_delta=-abs(penalty),
            issues=[issue],
            hard_fail=hard_fail,
        )

    def _expected_names(self, evidence: VerificationEvidence, config: dict) -> list[str]:
        configured = config.get("expected_names")
        candidates = list(_iter_name_values(configured))
        if not candidates:
            for field in NAME_FIELDS:
                candidates.extend(_iter_name_values(evidence.analysis.get(field)))
        if not candidates:
            candidates.extend(_iter_name_values(_fact_value(evidence.fact_bag, "verification.expected_names")))

        max_names = max(1, int(config.get("max_expected_names", 50) or 50))
        names = []
        seen = set()
        for candidate in candidates:
            cleaned = _clean_expected_name(candidate)
            if not cleaned:
                continue
            key = _normalize_path(cleaned)
            if key in seen:
                continue
            seen.add(key)
            names.append(cleaned)
            if len(names) >= max_names:
                break
        return names


def _fact_value(fact_bag: Any, key: str) -> Any:
    if fact_bag is not None and hasattr(fact_bag, "get"):
        return fact_bag.get(key)
    return None


def _iter_name_values(value: Any):
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, bytes):
        try:
            yield value.decode("utf-8", errors="replace")
        except Exception:
            return
        return
    if isinstance(value, dict):
        for key in ("name", "path", "file", "filename"):
            if key in value:
                yield from _iter_name_values(value.get(key))
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_name_values(item)


def _clean_expected_name(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip().strip("/")
    if not text:
        return ""
    parts = [part for part in text.split("/") if part not in {"", ".", ".."}]
    if not parts:
        return ""
    return "/".join(parts)


def _normalize_path(value: str) -> str:
    return "/".join(
        _normalize_name(part)
        for part in str(value or "").replace("\\", "/").split("/")
        if part
    )


def _normalize_name(value: str) -> str:
    return unicodedata.normalize("NFC", str(value or "")).casefold()
