import os
from typing import Any, Dict
from packrelic.contracts.rules import RuleEffect
from packrelic.contracts.detection import FactBag
from packrelic.detection.pipeline.rules.registry import register_rule
from packrelic.detection.pipeline.rules.base import RuleBase
from packrelic.support.extensions import normalize_extension_score_groups

@register_rule(name="extension", layer="scoring")
class ExtensionScoreRule(RuleBase):
    required_facts = {"file.path"}
    fact_requirements = []
    config_schema = {
        "extension_score_groups": {
            "type": "list[dict]",
            "required": False,
            "description": "Score groups assigned by file extension before content identity checks.",
        },
    }

    def minimum_score(self, config: Dict[str, Any]) -> int:
        scores = normalize_extension_score_groups(config.get("extension_score_groups", []))
        return min([0] + list(scores.values()))

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        path = facts.get("file.path")
        if not path:
            return RuleEffect.pass_()
            
        ext = os.path.splitext(path)[1].lower()
        scores = normalize_extension_score_groups(config.get("extension_score_groups", []))
        if ext in scores:
            return RuleEffect.add_score(scores[ext], reason=f"Matched extension {ext}")
            
        return RuleEffect.add_score(0, reason="No extension match")
