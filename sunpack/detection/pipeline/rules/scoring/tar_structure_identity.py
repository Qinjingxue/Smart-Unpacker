from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule
from sunpack.detection.pipeline.rules.scoring._fuzzy import add_component, fuzzy_effect_reason, naming_prior


@register_rule(name="tar_structure_identity", layer="scoring")
class TarStructureIdentityScoreRule(RuleBase):
    required_facts = {"tar.header_structure"}
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    score_group = "archive_format"
    config_schema: dict[str, dict[str, Any]] = {}

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> RuleEffect:
        del config
        structure = facts.get("tar.header_structure") or {}
        naming, label = naming_prior(facts, formats={"tar"}, extensions={".tar"})
        stored_checksum = int(structure.get("stored_checksum") or 0)
        checksum_matches = (
            stored_checksum > 0
            and stored_checksum == int(structure.get("computed_checksum") or -1)
        )
        # A non-empty TAR name field is not format-specific: for an arbitrary
        # binary it merely means that some byte in the first 100 bytes is not
        # zero.  Require a fixed-layout TAR anchor before weaker fields may
        # contribute supporting evidence.  This still admits checksum-damaged
        # ustar headers and V7/GNU headers whose numeric layout survives.
        has_binary_anchor = bool(
            structure.get("ustar_magic")
            or structure.get("fuzzy_numeric_fields_valid")
            or checksum_matches
        )
        if not has_binary_anchor:
            return RuleEffect.pass_()

        components: list[str] = []
        score = add_component(components, "ustar-marker", 2, bool(structure.get("ustar_magic")))
        score += add_component(components, "member-name", 1, bool(structure.get("fuzzy_name_nonempty")))
        score += add_component(
            components,
            "numeric-fields",
            2,
            bool(structure.get("fuzzy_numeric_fields_valid")),
        )
        score += add_component(components, "typeflag", 1, bool(structure.get("fuzzy_typeflag_valid")))
        score += add_component(components, "payload-range", 1, bool(structure.get("fuzzy_payload_in_range")))
        score += add_component(
            components,
            "header-checksum",
            1,
            checksum_matches,
        )
        score += add_component(components, label, naming, naming > 0)
        score += add_component(
            components,
            "invalid-numeric-fields",
            -2,
            bool(structure.get("ustar_magic")) and not bool(structure.get("fuzzy_numeric_fields_valid")),
        )

        facts.set("file.detected_ext", ".tar")
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)
        return RuleEffect.add_score(score, reason=fuzzy_effect_reason("TAR", components))
