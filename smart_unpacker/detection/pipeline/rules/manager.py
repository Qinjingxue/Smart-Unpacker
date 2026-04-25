from typing import Any, Dict, List

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleDecision
from smart_unpacker.detection.pipeline.rules.registry import discover_rules, get_rule_registry
from smart_unpacker.detection.pipeline.rules.config_validator import RuleConfigValidator
from smart_unpacker.detection.pipeline.rules.confirmation_runner import ConfirmationRunner
from smart_unpacker.detection.pipeline.rules.decision_policy import RuleDecisionPolicy
from smart_unpacker.detection.pipeline.rules.rule_preparer import RulePreparer
from smart_unpacker.detection.pipeline.rules.types import PreparedRule
from smart_unpacker.detection.pipeline.rules.fact_requirements import FactRequirement

class RuleManager:
    def __init__(
        self,
        config: Dict[str, Any],
        ensure_pool_facts=None,
        fact_config_defaults: dict[str, dict[str, Any]] | None = None,
    ):
        self.config = config
        self.fact_config_defaults = fact_config_defaults or {}
        discover_rules()
        self.ensure_pool_facts = ensure_pool_facts or self._missing_fact_scheduler
        self.registry = get_rule_registry()
        self.config_validator = RuleConfigValidator(self.registry)
        self.rule_preparer = RulePreparer(config, self.registry, self.config_validator)
        self.decision_policy = RuleDecisionPolicy(config)
        self.confirmation_runner = ConfirmationRunner(
            self.decision_policy,
            lambda layer: self._prepare_rules(layer),
            lambda fact_bags, required_facts, fact_configs=None: self.ensure_pool_facts(
                fact_bags,
                required_facts,
                fact_configs,
            ),
        )

    def validate_config(self) -> list[str]:
        return self.config_validator.validate_pipeline_config(self.config)

    def _prepare_rules(self, layer: str) -> List[PreparedRule]:
        return self.rule_preparer.prepare(layer)

    def _missing_fact_scheduler(
        self,
        fact_bags: List[FactBag],
        required_facts: set[str],
        fact_configs: dict[str, dict[str, Any]] | None = None,
    ):
        for bag in fact_bags:
            for fact_name in required_facts:
                if not bag.has(fact_name):
                    bag.mark_missing(fact_name)

    def _rule_fact_requirements(self, rule: PreparedRule) -> list[FactRequirement]:
        requirements = list(getattr(rule.instance, "fact_requirements", []) or [])
        if requirements:
            return requirements
        return [FactRequirement(fact_name) for fact_name in rule.instance.required_facts]

    def _effective_fact_config(self, fact_name: str, rule_config: dict[str, Any]) -> dict[str, Any]:
        effective = dict(self.fact_config_defaults.get(fact_name, {}))
        effective.update(rule_config)
        return effective

    def _ensure_scoring_facts(self, fact_bags: List[FactBag], scoring_rules: List[PreparedRule]):
        prerequisite_facts: set[str] = set()
        rule_requirements: list[tuple[PreparedRule, list[FactRequirement]]] = []
        for rule in scoring_rules:
            requirements = self._rule_fact_requirements(rule)
            rule_requirements.append((rule, requirements))
            for requirement in requirements:
                prerequisite_facts.update(requirement.prerequisite_facts)

        if prerequisite_facts:
            self.ensure_pool_facts(fact_bags, prerequisite_facts)

        for bag in fact_bags:
            active_facts: list[str] = []
            seen_active_facts: set[str] = set()
            fact_configs: dict[str, dict[str, Any]] = {}
            for rule, requirements in rule_requirements:
                for requirement in requirements:
                    effective_config = self._effective_fact_config(requirement.fact_name, rule.config)
                    if not requirement.matches(bag, effective_config):
                        continue
                    if requirement.fact_name not in seen_active_facts:
                        active_facts.append(requirement.fact_name)
                        seen_active_facts.add(requirement.fact_name)
                    fact_configs.setdefault(requirement.fact_name, effective_config)
            if active_facts:
                self.ensure_pool_facts([bag], set(active_facts), fact_configs)

    def evaluate_pool(self, fact_bags: List[FactBag]) -> Dict[FactBag, RuleDecision]:
        decisions: Dict[FactBag, RuleDecision] = {}
        surviving = list(fact_bags)

        for rule in self._prepare_rules("hard_stop"):
            fact_configs = {fact_name: rule.config for fact_name in rule.instance.required_facts}
            self.ensure_pool_facts(surviving, rule.instance.required_facts, fact_configs)

            next_surviving: List[FactBag] = []
            for bag in surviving:
                effect = rule.instance.evaluate(bag, rule.config)
                if effect.decision == "stop":
                    decisions[bag] = RuleDecision(
                        should_extract=False,
                        total_score=0,
                        matched_rules=[rule.name],
                        stop_reason=effect.reason,
                        decision="not_archive",
                        decision_stage="hard_stop",
                        discarded_at="hard_stop",
                        deciding_rule=rule.name,
                    )
                else:
                    next_surviving.append(bag)
            surviving = next_surviving
            if not surviving:
                return decisions

        scoring_rules = self._prepare_rules("scoring")
        self._ensure_scoring_facts(surviving, scoring_rules)

        for bag in surviving:
            total_score = 0
            matched_rules: List[str] = []
            score_breakdown: list[dict[str, Any]] = []
            for rule in scoring_rules:
                effect = rule.instance.evaluate(bag, rule.config)
                if effect.decision == "score":
                    total_score += effect.score
                    score_breakdown.append({
                        "rule": rule.name,
                        "score": effect.score,
                        "reason": effect.reason,
                    })
                    if effect.score != 0:
                        matched_rules.append(rule.name)
            confirmation_decision, confirmation_trace = self.confirmation_runner.run(
                bag,
                total_score,
                matched_rules,
                score_breakdown=score_breakdown,
            )
            if confirmation_decision is not None:
                decisions[bag] = confirmation_decision
            else:
                decisions[bag] = self.decision_policy.finalize_scoring_decision(
                    bag,
                    total_score,
                    matched_rules,
                    score_breakdown=score_breakdown,
                    confirmation=confirmation_trace,
                )

        return decisions
