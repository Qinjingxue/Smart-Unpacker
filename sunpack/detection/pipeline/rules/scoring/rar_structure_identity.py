from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule
from sunpack.detection.pipeline.rules.scoring._fuzzy import (
    add_component,
    fuzzy_effect_reason,
    naming_prior,
    split_layout_prior,
)


@register_rule(name="rar_structure_identity", layer="scoring")
class RarStructureIdentityScoreRule(RuleBase):
    required_facts = {"rar.structure"}
    produced_facts = {"file.detected_ext", "file.magic_matched", "file.probe_detected_archive", "file.probe_offset"}
    config_schema: dict[str, dict[str, Any]] = {}

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> RuleEffect:
        del config
        structure = facts.get("rar.structure") or {}
        if not structure.get("magic_matched"):
            return RuleEffect.pass_()

        version = int(structure.get("version") or 0)
        header_type = int(structure.get("first_header_type") or 0)
        header_size = int(structure.get("first_header_size") or 0)
        type_ok = (version == 4 and 0x73 <= header_type <= 0x7B) or (version == 5 and header_type in {1, 4})
        components: list[str] = []
        score = add_component(components, "signature", 2, True)
        score += add_component(components, "version", 1, version in {4, 5})
        score += add_component(components, "header-type", 1, type_ok)
        score += add_component(components, "header-size", 1, header_size >= (7 if version == 4 else 1))
        score += add_component(components, "header-CRC", 1, bool(structure.get("header_crc_ok")))
        score += add_component(
            components,
            "following-block",
            2,
            bool(structure.get("second_block_ok") or structure.get("block_walk_ok")),
        )
        naming, label = naming_prior(
            facts,
            formats={"rar", "rar4", "rar5"},
            extensions={".rar", ".r00", ".part1.rar", ".part01.rar"},
        )
        score += add_component(components, label, naming, naming > 0)
        split, split_label = split_layout_prior(facts, formats={"rar", "rar4", "rar5"})
        score += add_component(components, split_label, split, split > 0)
        score += add_component(components, "unknown-header-type", -2, version in {4, 5} and not type_ok)

        facts.set("file.detected_ext", ".rar")
        facts.set("file.magic_matched", True)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        return RuleEffect.add_score(score, reason=fuzzy_effect_reason("RAR", components))
