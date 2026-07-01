from typing import Any, Dict

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


DEFAULT_RAR_STRUCTURE_SCORE = 5


@register_rule(name="rar_structure_identity", layer="scoring")
class RarStructureIdentityScoreRule(RuleBase):
    required_facts = {"rar.structure"}
    fact_requirements = []
    produced_facts = {"file.detected_ext", "file.magic_matched", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "structure_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_RAR_STRUCTURE_SCORE,
            "description": "Score for a plausible RAR4/RAR5 first-header structure.",
        },
        "magic_score": {
            "type": "int",
            "required": True,
            "description": "Score for a RAR magic signature without stronger first-header structure.",
        },
        "block_walk_score": {
            "type": "int",
            "required": True,
            "description": "Score for a RAR main header plus a valid following block/header.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("rar.structure") or {}
        if not structure.get("plausible") and not structure.get("magic_matched"):
            return RuleEffect.pass_()
        facts.set("file.detected_ext", ".rar")
        facts.set("file.magic_matched", True)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        if structure.get("block_walk_ok"):
            score = config["block_walk_score"]
            reason = f"RAR structure: RAR{structure.get('version') or ''} second block walk"
        elif structure.get("plausible"):
            score = config.get("structure_score", DEFAULT_RAR_STRUCTURE_SCORE)
            reason = f"RAR structure: RAR{structure.get('version') or ''} first header"
        else:
            score = config["magic_score"]
            reason = "RAR structure: magic signature"
        if not score:
            return RuleEffect.pass_()
        return RuleEffect.add_score(score, reason=reason)
