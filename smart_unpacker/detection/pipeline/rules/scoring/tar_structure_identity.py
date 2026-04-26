from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.registry import register_rule


DEFAULT_TAR_HEADER_SCORE = 5
DEFAULT_USTAR_HEADER_SCORE = 6
DEFAULT_TAR_ENTRY_WALK_SCORE = 7


@register_rule(name="tar_structure_identity", layer="scoring")
class TarStructureIdentityScoreRule(RuleBase):
    required_facts = {"tar.header_structure"}
    fact_requirements = []
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "tar_header_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_TAR_HEADER_SCORE,
            "description": "Score for a plausible TAR header checksum.",
        },
        "ustar_header_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_USTAR_HEADER_SCORE,
            "description": "Score for a plausible ustar header checksum and magic marker.",
        },
        "entry_walk_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_TAR_ENTRY_WALK_SCORE,
            "description": "Score for a TAR header walk across one or more entries.",
        },
        "max_entries_to_walk": {
            "type": "int",
            "required": False,
            "description": "Maximum TAR entries checked by the TAR structure processor.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("tar.header_structure") or {}
        if not structure.get("plausible"):
            return RuleEffect.pass_()

        facts.set("file.detected_ext", ".tar")
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)

        if structure.get("entry_walk_ok") and structure.get("ustar_magic"):
            score = config.get("entry_walk_score", DEFAULT_TAR_ENTRY_WALK_SCORE)
            reason = "TAR structure: ustar header checksum and entry walk"
        elif structure.get("ustar_magic"):
            score = config.get("ustar_header_score", DEFAULT_USTAR_HEADER_SCORE)
            reason = "TAR structure: ustar header checksum"
        else:
            score = config.get("tar_header_score", DEFAULT_TAR_HEADER_SCORE)
            reason = "TAR structure: header checksum"
        if not score:
            return RuleEffect.pass_()
        return RuleEffect.add_score(score, reason=reason)
