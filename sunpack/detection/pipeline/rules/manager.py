from typing import Any, Dict, List

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleDecision
from sunpack.detection.pipeline.rules.registry import discover_rules, get_rule_registry
from sunpack.detection.pipeline.rules.config_validator import RuleConfigValidator
from sunpack.detection.pipeline.rules.decision_policy import RuleDecisionPolicy
from sunpack.detection.pipeline.rules.rule_preparer import RulePreparer
from sunpack.detection.pipeline.rules.types import PreparedRule
from sunpack.detection.pipeline.rules.fact_requirements import FactRequirement

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

    def validate_config(self) -> list[str]:
        return self.config_validator.validate_pipeline_config(self.config)

    def finalize_scored_evidence(
        self,
        fact_bag: FactBag,
        total_score: int,
        matched_rules: List[str],
        score_breakdown: list[dict[str, Any]] | None = None,
    ) -> RuleDecision:
        return self.decision_policy.finalize_scoring_decision(
            fact_bag,
            total_score,
            matched_rules,
            score_breakdown=score_breakdown,
        )

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

    def _ensure_scoring_rule_facts(self, fact_bags: List[FactBag], rule: PreparedRule):
        if not fact_bags:
            return
        requirements = self._rule_fact_requirements(rule)
        prerequisite_facts: set[str] = set()
        for requirement in requirements:
            prerequisite_facts.update(requirement.prerequisite_facts)
        if prerequisite_facts:
            self.ensure_pool_facts(fact_bags, prerequisite_facts)

        active_groups: dict[frozenset[str], list[FactBag]] = {}
        for bag in fact_bags:
            active_facts = {
                requirement.fact_name
                for requirement in requirements
                if requirement.matches(bag, self._effective_fact_config(requirement.fact_name, rule.config))
            }
            if active_facts:
                active_groups.setdefault(frozenset(active_facts), []).append(bag)

        for active_facts, active_bags in active_groups.items():
            fact_configs = {
                fact_name: self._effective_fact_config(fact_name, rule.config)
                for fact_name in active_facts
            }
            self.ensure_pool_facts(active_bags, set(active_facts), fact_configs)

    def _remaining_minimum_score(self, scoring_rules: List[PreparedRule]) -> int:
        minimum = 0
        for rule in scoring_rules:
            minimum += int(rule.instance.minimum_score(rule.config))
        return minimum

    def _scoring_decision_fixed(
        self,
        total_score: int,
        remaining_rules: List[PreparedRule],
    ) -> bool:
        threshold = self.decision_policy.archive_threshold()
        return total_score >= threshold and total_score + self._remaining_minimum_score(remaining_rules) >= threshold

    @staticmethod
    def _routing_values(bag: FactBag) -> tuple[set[str], set[str]]:
        formats: set[str] = set()
        extensions: set[str] = set()
        archive_input = bag.get("archive.input") or {}
        for value in (
            archive_input.get("format_hint") if isinstance(archive_input, dict) else "",
            bag.get("relation.format_hint"),
            bag.get("relation.split_family"),
        ):
            normalized = str(value or "").lower().lstrip(".")
            if normalized:
                formats.add(normalized)

        for value in (
            bag.get("candidate.logical_name"),
            bag.get("file.logical_name"),
            bag.get("candidate.entry_path"),
            bag.get("file.path"),
        ):
            name = str(value or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
            if not name:
                continue
            parts = name.split(".")
            for count in (1, 2):
                if len(parts) > count:
                    extensions.add("." + ".".join(parts[-count:]))
        return formats, extensions

    def _ordered_precheck_rules(self, bag: FactBag, rules: List[PreparedRule]) -> List[PreparedRule]:
        formats, extensions = self._routing_values(bag)
        guards = [rule for rule in rules if getattr(rule.instance, "precheck_phase", "identity") == "guard"]
        identity = [rule for rule in rules if getattr(rule.instance, "precheck_phase", "identity") == "identity"]
        tails = [rule for rule in rules if getattr(rule.instance, "precheck_phase", "identity") == "tail"]
        promoted: list[PreparedRule] = []
        remaining: list[PreparedRule] = []
        for rule in identity:
            rule_formats = set(getattr(rule.instance, "routing_formats", set()) or set())
            rule_extensions = set(getattr(rule.instance, "routing_extensions", set()) or set())
            matches = bool(rule_formats & formats or rule_extensions & extensions)
            if getattr(rule.instance, "can_be_promoted", False) and matches:
                promoted.append(rule)
            else:
                remaining.append(rule)
        return guards + promoted + remaining + tails

    def _run_precheck(self, fact_bags: List[FactBag]) -> tuple[Dict[FactBag, RuleDecision], List[FactBag]]:
        decisions: Dict[FactBag, RuleDecision] = {}
        surviving: List[FactBag] = []
        configured_rules = self._prepare_rules("precheck")
        for bag in fact_bags:
            terminal = False
            for rule in self._ordered_precheck_rules(bag, configured_rules):
                requirements = self._rule_fact_requirements(rule)
                prerequisite_facts: set[str] = set()
                for requirement in requirements:
                    prerequisite_facts.update(requirement.prerequisite_facts)
                if prerequisite_facts:
                    self.ensure_pool_facts([bag], prerequisite_facts)
                active_facts = {
                    requirement.fact_name
                    for requirement in requirements
                    if requirement.matches(bag, self._effective_fact_config(requirement.fact_name, rule.config))
                }
                if active_facts:
                    fact_configs = {
                        fact_name: self._effective_fact_config(fact_name, rule.config)
                        for fact_name in active_facts
                    }
                    self.ensure_pool_facts([bag], set(active_facts), fact_configs)
                if requirements and not active_facts:
                    continue
                effect = self._evaluate_precheck_rule(bag, rule)
                if effect.decision in {"reject", "accept"}:
                    accepted = effect.decision == "accept"
                    decisions[bag] = RuleDecision(
                        should_extract=accepted,
                        total_score=0,
                        matched_rules=[rule.name],
                        stop_reason=effect.reason,
                        decision="archive" if accepted else "not_archive",
                        decision_stage="precheck",
                        discarded_at=None if accepted else "precheck",
                        deciding_rule=rule.name,
                    )
                    terminal = True
                    break
                if effect.decision != "pass":
                    raise ValueError(f"Precheck rule {rule.name} returned unsupported effect: {effect.decision}")
            if not terminal:
                surviving.append(bag)

        return decisions, surviving

    def _evaluate_precheck_rule(self, bag: FactBag, rule: PreparedRule):
        requested_facts: set[str] = set()
        while True:
            effect = rule.instance.evaluate(bag, rule.config)
            if effect.decision != "require":
                return effect
            required_facts = set(effect.required_facts)
            new_facts = required_facts - requested_facts
            if not new_facts:
                raise ValueError(
                    f"Precheck rule {rule.name} repeatedly requested unavailable facts: "
                    f"{', '.join(sorted(required_facts))}"
                )
            fact_configs = {
                fact_name: self._effective_fact_config(fact_name, rule.config)
                for fact_name in new_facts
            }
            self.ensure_pool_facts([bag], new_facts, fact_configs)
            requested_facts.update(new_facts)

    def evaluate_pool(self, fact_bags: List[FactBag]) -> Dict[FactBag, RuleDecision]:
        decisions, surviving = self._run_precheck(fact_bags)
        if not surviving:
            return decisions

        scoring_rules = self._prepare_rules("scoring")
        scoring_state: dict[FactBag, dict[str, Any]] = {
            bag: {
                "total_score": 0,
                "matched_rules": [],
                "score_breakdown": [],
            }
            for bag in surviving
        }
        active_bags = list(surviving)

        for index, rule in enumerate(scoring_rules):
            if not active_bags:
                break
            self._ensure_scoring_rule_facts(active_bags, rule)
            remaining_rules = scoring_rules[index + 1 :]
            next_active_bags: List[FactBag] = []
            for bag in active_bags:
                state = scoring_state[bag]
                effect = rule.instance.evaluate(bag, rule.config)
                if effect.decision == "score":
                    state["total_score"] += effect.score
                    state["score_breakdown"].append({
                        "rule": rule.name,
                        "score": effect.score,
                        "reason": effect.reason,
                    })
                    if effect.score != 0:
                        state["matched_rules"].append(rule.name)
                if not self._scoring_decision_fixed(
                    state["total_score"],
                    remaining_rules,
                ):
                    next_active_bags.append(bag)
            active_bags = next_active_bags

        for bag in surviving:
            state = scoring_state[bag]
            total_score = state["total_score"]
            matched_rules: List[str] = list(state["matched_rules"])
            score_breakdown: list[dict[str, Any]] = list(state["score_breakdown"])
            decisions[bag] = self.finalize_scored_evidence(
                bag,
                total_score,
                matched_rules,
                score_breakdown=score_breakdown,
            )

        return decisions
