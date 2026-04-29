from typing import Any, Dict

from packrelic.contracts.detection import FactBag
from packrelic.contracts.rules import RuleEffect
from packrelic.detection.pipeline.processors.modules.format_structure.seven_zip import DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES
from packrelic.detection.pipeline.rules.base import RuleBase
from packrelic.detection.pipeline.rules.registry import register_rule


@register_rule(name="seven_zip_structure_accept", layer="precheck")
class SevenZipStructureAcceptRule(RuleBase):
    required_facts = {"7z.structure"}
    produced_facts = {"file.detected_ext", "file.magic_matched", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "max_next_header_check_bytes": {
            "type": "int",
            "required": False,
            "default": DEFAULT_MAX_NEXT_HEADER_CHECK_BYTES,
            "description": "Maximum 7z next-header bytes read to verify the next-header CRC before precheck accept.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("7z.structure") or {}
        if not structure.get("plausible") or not structure.get("strong_accept"):
            return RuleEffect.pass_()

        facts.set("file.detected_ext", ".7z")
        facts.set("file.magic_matched", True)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        return RuleEffect.accept("7z structure accept: start header and next header CRC")
