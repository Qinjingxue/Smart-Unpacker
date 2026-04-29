from typing import Any, Dict

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


DEFAULT_ARCHIVE_CONTAINER_SCORE = 5


@register_rule(name="archive_container_identity", layer="scoring")
class ArchiveContainerIdentityScoreRule(RuleBase):
    required_facts = {"archive.container_structure"}
    fact_requirements = []
    produced_facts = {"file.detected_ext", "file.probe_detected_archive", "file.probe_offset"}
    config_schema = {
        "container_score": {
            "type": "int",
            "required": False,
            "default": DEFAULT_ARCHIVE_CONTAINER_SCORE,
            "description": "Score for a plausible CAB, ARJ, or CPIO container structure.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        structure = facts.get("archive.container_structure") or {}
        if not structure.get("plausible"):
            return RuleEffect.pass_()

        detected_ext = structure.get("detected_ext") or ""
        if detected_ext:
            facts.set("file.detected_ext", detected_ext)
        facts.set("file.probe_detected_archive", True)
        facts.set("file.probe_offset", 0)

        score = config.get("container_score", DEFAULT_ARCHIVE_CONTAINER_SCORE)
        if not score:
            return RuleEffect.pass_()
        archive_format = structure.get("format") or detected_ext or "archive_container"
        confidence = structure.get("confidence") or "unknown"
        return RuleEffect.add_score(
            score,
            reason=f"Archive container structure {archive_format} ({confidence})",
        )
