from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.processors.modules.format_structure.rar import DEFAULT_MAX_FIRST_HEADER_CHECK_BYTES
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.registry import register_rule


@register_rule(name="rar_structure_accept", layer="precheck")
class RarStructureAcceptRule(RuleBase):
    required_facts = {"rar.structure"}
    produced_facts = {"file.detected_ext", "file.magic_matched", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "max_first_header_check_bytes": {
            "type": "int",
            "required": False,
            "default": DEFAULT_MAX_FIRST_HEADER_CHECK_BYTES,
            "description": "Maximum RAR first-header bytes read to verify the header CRC before precheck accept.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("rar.structure") or {}
        if not structure.get("plausible") or not structure.get("strong_accept"):
            return RuleEffect.pass_()

        facts.set("file.detected_ext", ".rar")
        facts.set("file.magic_matched", True)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        return RuleEffect.accept("RAR structure accept: main header and header CRC")
