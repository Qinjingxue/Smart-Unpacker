from typing import Dict, Any
from sunpack.contracts.rules import RuleEffect
from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.rules.fact_requirements import FactRequirement

class RuleBase:
    required_facts: set[str] = set()
    fact_requirements: list[FactRequirement] = []
    produced_facts: set[str] = set()
    # Scoring rules in the same group represent mutually exclusive
    # hypotheses.  The manager selects the strongest hypothesis instead of
    # adding their scores or allowing evaluation order to choose its facts.
    score_group: str | None = None
    config_schema: Dict[str, Dict[str, Any]] = {}
    # Routing metadata is only an execution hint.  A match may move a strict
    # identity precheck earlier, but never changes the rule's decision.
    routing_formats: set[str] = set()
    routing_extensions: set[str] = set()
    can_be_promoted: bool = False

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        raise NotImplementedError()

    def minimum_score(self, config: Dict[str, Any]) -> int:
        minimum = 0
        for key, schema in self.config_schema.items():
            if schema.get("type") != "int":
                continue
            if "score" not in key and "penalty" not in key:
                continue
            value = config.get(key, schema.get("default", 0))
            try:
                minimum = min(minimum, int(value))
            except (TypeError, ValueError):
                continue
        return minimum
