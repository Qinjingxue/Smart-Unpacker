from typing import Any, List

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleDecision


class RuleDecisionPolicy:
    def __init__(self, config: dict[str, Any]):
        self.config = config

    def finalize_scoring_decision(
        self,
        fact_bag: FactBag,
        total_score: int,
        matched_rules: List[str],
        score_breakdown: list[dict[str, Any]] | None = None,
        confirmation: dict[str, Any] | None = None,
    ) -> RuleDecision:
        threshold = self.archive_threshold()
        maybe_threshold = self.maybe_threshold()

        should_extract = total_score >= threshold
        decision = "archive" if should_extract else "not_archive"
        discarded_at = None

        if not should_extract and total_score >= maybe_threshold:
            decision = "maybe_archive"
            discarded_at = "scoring_threshold"
        elif not should_extract:
            discarded_at = "scoring_threshold"

        return RuleDecision(
            should_extract=should_extract,
            total_score=total_score,
            matched_rules=matched_rules,
            decision=decision,
            decision_stage="scoring",
            discarded_at=discarded_at,
            deciding_rule=matched_rules[-1] if matched_rules else None,
            score_breakdown=list(score_breakdown or []),
            confirmation=dict(confirmation or {}),
        )

    def archive_threshold(self) -> int:
        thresholds = self._thresholds()
        return int(thresholds.get("archive_score_threshold", 6))

    def maybe_threshold(self) -> int:
        thresholds = self._thresholds()
        return int(thresholds.get("maybe_archive_threshold", 3))

    def confirmation_bounds(self) -> tuple[int, int]:
        return self.maybe_threshold(), self.archive_threshold() - 1

    def should_enter_confirmation(self, total_score: int) -> bool:
        min_score, max_score = self.confirmation_bounds()
        return min_score <= total_score <= max_score

    def _thresholds(self) -> dict[str, Any]:
        thresholds = self.config.get("thresholds", {})
        return thresholds if isinstance(thresholds, dict) else {}
