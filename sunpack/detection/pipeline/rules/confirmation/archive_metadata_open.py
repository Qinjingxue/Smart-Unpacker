from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import ConfirmationEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


@register_rule("archive_metadata_open", "confirmation")
class ArchiveMetadataOpenRule(RuleBase):
    required_facts = {"archive.metadata_open"}
    produced_facts = {"file.detected_ext", "file.probe_detected_archive"}
    config_schema = {
        "always_run": {"type": "bool", "required": False, "default": True},
        "timeout_seconds": {"type": "float", "required": False, "default": 1.5},
        "candidate_extensions": {"type": "list[str]", "required": False},
    }

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> ConfirmationEffect:
        result = facts.get("archive.metadata_open") or {}
        if not result.get("confirmed"):
            return ConfirmationEffect.pass_()
        archive_type = str(result.get("type") or "archive")
        if archive_type:
            facts.set("file.detected_ext", f".{archive_type.lstrip('.').lower()}")
        facts.set("file.probe_detected_archive", True)
        return ConfirmationEffect.confirm(f"Bounded metadata open confirmed {archive_type} archive")
