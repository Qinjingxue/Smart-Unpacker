from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.registry import register_rule


@register_rule(name="tar_structure_accept", layer="precheck")
class TarStructureAcceptRule(RuleBase):
    required_facts = {"tar.header_structure"}
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "max_entries_to_walk": {
            "type": "int",
            "required": False,
            "description": "Maximum TAR entries checked by the TAR structure processor.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("tar.header_structure") or {}
        if not structure.get("plausible") or not structure.get("ustar_magic") or not structure.get("entry_walk_ok"):
            return RuleEffect.pass_()

        facts.set("file.detected_ext", ".tar")
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        return RuleEffect.accept("TAR structure accept: ustar header checksum")
