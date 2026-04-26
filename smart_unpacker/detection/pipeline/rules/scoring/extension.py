import os
from typing import Any, Dict
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection.pipeline.rules.registry import register_rule
from smart_unpacker.detection.pipeline.rules.base import RuleBase


def normalize_extension_score_groups(values) -> dict[str, int]:
    if not isinstance(values, list):
        return {}
    normalized = {}
    for group in values:
        if not isinstance(group, dict):
            continue
        try:
            score = int(group.get("score"))
        except (TypeError, ValueError):
            continue
        for ext in group.get("extensions") or []:
            if not isinstance(ext, str) or not ext.strip():
                continue
            normalized_ext = ext.strip().lower()
            normalized[normalized_ext if normalized_ext.startswith(".") else f".{normalized_ext}"] = score
    return normalized

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
