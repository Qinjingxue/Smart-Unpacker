from typing import Dict, Any
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection.pipeline.rules.fact_requirements import FactRequirement

class RuleBase:
    required_facts: set[str] = set()
    fact_requirements: list[FactRequirement] = []
    produced_facts: set[str] = set()
    config_schema: Dict[str, Dict[str, Any]] = {}

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        raise NotImplementedError()
