from collections.abc import Callable
from typing import Any
from typing import List

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleDecision
from sunpack.detection.pipeline.rules.decision_policy import RuleDecisionPolicy
from sunpack.detection.pipeline.rules.types import PreparedRule


class ConfirmationRunner:
    def __init__(
        self,
        decision_policy: RuleDecisionPolicy,
        prepare_rules: Callable[[str], List[PreparedRule]],
        ensure_pool_facts: Callable[[list[FactBag], set[str], dict[str, dict] | None], None],
    ):
        self.decision_policy = decision_policy
        self.prepare_rules = prepare_rules
        self.ensure_pool_facts = ensure_pool_facts

    def run(
        self,
        fact_bag: FactBag,
        total_score: int,
        matched_rules: List[str],
        score_breakdown: list[dict[str, Any]] | None = None,
    ) -> tuple[RuleDecision | None, dict[str, Any]]:
        trace: dict[str, Any] = {
            "entered": False,
            "evaluated_rules": [],
            "decision": "not_entered",
        }
        if not self.decision_policy.should_enter_confirmation(total_score):
            return None, trace

        trace["entered"] = True
        trace["decision"] = "pass"
        for rule in self.prepare_rules("confirmation"):
            if not self._rule_applies(rule, total_score):
                continue
            fact_configs = {fact_name: rule.config for fact_name in rule.instance.required_facts}
            self.ensure_pool_facts([fact_bag], rule.instance.required_facts, fact_configs)
            effect = rule.instance.evaluate(fact_bag, rule.config)
            trace["evaluated_rules"].append({
                "rule": rule.name,
                "decision": effect.decision,
                "reason": effect.reason,
            })
            if effect.decision == "pass":
                continue

            matched = list(matched_rules)
            matched.append(rule.name)
            trace["decision"] = effect.decision
            trace["deciding_rule"] = rule.name
            trace["reason"] = effect.reason
            if effect.decision == "confirm":
                return RuleDecision(
                    should_extract=True,
                    total_score=total_score,
                    matched_rules=matched,
                    stop_reason=effect.reason,
                    decision="archive",
                    decision_stage="confirmation",
                    discarded_at=None,
                    deciding_rule=rule.name,
                    score_breakdown=list(score_breakdown or []),
                    confirmation=trace,
                ), trace
            if effect.decision == "reject":
                return RuleDecision(
                    should_extract=False,
                    total_score=total_score,
                    matched_rules=matched,
                    stop_reason=effect.reason,
                    decision="not_archive",
                    decision_stage="confirmation",
                    discarded_at="confirmation",
                    deciding_rule=rule.name,
                    score_breakdown=list(score_breakdown or []),
                    confirmation=trace,
                ), trace
        return None, trace

    def _rule_applies(self, rule: PreparedRule, total_score: int) -> bool:
        global_min, global_max = self.decision_policy.confirmation_bounds()
        score_min = int(rule.config.get("score_min", global_min))
        score_max = int(rule.config.get("score_max", global_max))
        return score_min <= total_score <= score_max
