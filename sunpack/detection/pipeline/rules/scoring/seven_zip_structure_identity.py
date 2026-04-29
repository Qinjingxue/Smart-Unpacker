from typing import Any, Dict

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


DEFAULT_SEVEN_Z_STRUCTURE_SCORE = 5
DEFAULT_SEVEN_Z_MAGIC_SCORE = 2
DEFAULT_SEVEN_Z_NID_SCORE = 6


@register_rule(name="seven_zip_structure_identity", layer="scoring")
class SevenZipStructureIdentityScoreRule(RuleBase):
    required_facts = {"7z.structure"}
    fact_requirements = []
    produced_facts = {"file.detected_ext", "file.magic_matched", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "structure_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_SEVEN_Z_STRUCTURE_SCORE,
            "description": "Score for a plausible 7z start-header structure.",
        },
        "magic_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_SEVEN_Z_MAGIC_SCORE,
            "description": "Score for a 7z magic signature without stronger start-header structure.",
        },
        "next_header_nid_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_SEVEN_Z_NID_SCORE,
            "description": "Score for a 7z next header whose CRC and first NID are both valid.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("7z.structure") or {}
        if not structure.get("plausible") and not structure.get("magic_matched"):
            return RuleEffect.pass_()
        facts.set("file.detected_ext", ".7z")
        facts.set("file.magic_matched", True)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        if structure.get("next_header_semantic_ok"):
            score = config.get("next_header_nid_score", DEFAULT_SEVEN_Z_NID_SCORE)
            reason = "7z structure: next header CRC and NID"
        elif structure.get("plausible"):
            score = config.get("structure_score", DEFAULT_SEVEN_Z_STRUCTURE_SCORE)
            reason = "7z structure: start header CRC and next header range"
        else:
            score = config.get("magic_score", DEFAULT_SEVEN_Z_MAGIC_SCORE)
            reason = "7z structure: magic signature"
        if not score:
            return RuleEffect.pass_()
        return RuleEffect.add_score(score, reason=reason)
