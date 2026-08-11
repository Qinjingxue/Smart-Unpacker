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


@register_rule(name="seven_zip_structure_identity", layer="scoring")
class SevenZipStructureIdentityScoreRule(RuleBase):
    required_facts = {"7z.structure"}
    produced_facts = {"file.detected_ext", "file.magic_matched", "file.probe_detected_archive", "file.probe_offset"}
    score_group = "archive_format"
    config_schema: dict[str, dict[str, Any]] = {}

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> RuleEffect:
        del config
        structure = facts.get("7z.structure") or {}
        if not structure.get("magic_matched"):
            return RuleEffect.pass_()

        components: list[str] = []
        score = add_component(components, "signature", 2, True)
        score += add_component(
            components,
            "version",
            1,
            int(structure.get("version_major") or 0) == 0,
        )
        next_offset = int(structure.get("next_header_offset") or 0)
        next_size = int(structure.get("next_header_size") or 0)
        score += add_component(
            components,
            "next-header-range",
            2,
            next_size > 0 and next_offset >= 0 and str(structure.get("error") or "") != "next_header_out_of_range",
        )
        score += add_component(components, "start-header-CRC", 1, bool(structure.get("start_header_crc_ok")))
        score += add_component(
            components,
            "next-header-anchor",
            2,
            bool(structure.get("next_header_crc_ok") or structure.get("next_header_nid_valid")),
        )
        naming, label = naming_prior(facts, formats={"7z"}, extensions={".7z", ".7z.001", ".001"})
        score += add_component(components, label, naming, naming > 0)
        split, split_label = split_layout_prior(facts, formats={"7z"})
        score += add_component(components, split_label, split, split > 0)
        score += add_component(
            components,
            "unsupported-version",
            -2,
            int(structure.get("version_major") or 0) != 0 and split == 0,
        )

        facts.set("file.detected_ext", ".7z")
        facts.set("file.magic_matched", True)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        return RuleEffect.add_score(score, reason=fuzzy_effect_reason("7z", components))
