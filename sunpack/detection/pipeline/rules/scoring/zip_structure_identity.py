from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.fact_requirements import FactRequirement, MagicBytesStartsWith
from sunpack.detection.pipeline.rules.registry import register_rule
from sunpack.detection.pipeline.rules.scoring._fuzzy import (
    add_component,
    fuzzy_effect_reason,
    naming_prior,
    split_layout_prior,
)


ZIP_START_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


@register_rule(name="zip_structure_identity", layer="scoring")
class ZipStructureIdentityScoreRule(RuleBase):
    required_facts = {"zip.local_header", "zip.eocd_structure"}
    fact_requirements = [
        FactRequirement("zip.local_header"),
        FactRequirement("zip.eocd_structure", MagicBytesStartsWith(ZIP_START_MAGICS)),
    ]
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    config_schema: dict[str, dict[str, Any]] = {}

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> RuleEffect:
        del config
        local = facts.get("zip.local_header") or {}
        eocd = facts.get("zip.eocd_structure") or {}
        local_magic = bool(local.get("magic_matched"))
        eocd_candidate = bool(eocd.get("eocd_candidate_found") or eocd.get("magic_matched"))
        if not local_magic and not eocd_candidate:
            return RuleEffect.pass_()

        components: list[str] = []
        score = 0
        score += add_component(components, "local-signature", 2, local_magic)
        score += add_component(components, "local-fields", 2, bool(local.get("plausible")))
        score += add_component(components, "EOCD-signature", 2, eocd_candidate)
        declared_cd = bool(
            eocd.get("eocd_candidate_declared_entry_count_present")
            or eocd.get("eocd_candidate_declared_cd_offset_present")
            or int(eocd.get("eocd_candidate_cd_size") or 0) > 0
        )
        score += add_component(components, "EOCD-fields", 1, eocd_candidate and declared_cd)
        score += add_component(
            components,
            "central-directory-anchor",
            1,
            bool(eocd.get("central_directory_present") or eocd.get("central_directory_walk_ok")),
        )
        naming, label = naming_prior(
            facts,
            formats={"zip"},
            extensions={".zip", ".zipx", ".jar", ".apk", ".docx", ".xlsx", ".z01"},
        )
        score += add_component(components, label, naming, naming > 0)
        split, split_label = split_layout_prior(facts, formats={"zip"})
        score += add_component(components, split_label, split, split > 0)
        delta = eocd.get("eocd_candidate_comment_available_delta")
        score += add_component(
            components,
            "damaged-EOCD-length",
            -1,
            eocd_candidate and delta not in (None, 0) and abs(int(delta)) > 65535,
        )
        if score <= 0:
            return RuleEffect.pass_()

        facts.set("file.detected_ext", ".zip")
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", int(eocd.get("archive_offset") or 0))
        return RuleEffect.add_score(score, reason=fuzzy_effect_reason("ZIP", components))
