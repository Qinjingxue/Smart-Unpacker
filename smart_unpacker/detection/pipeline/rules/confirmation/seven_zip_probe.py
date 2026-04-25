from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import ConfirmationEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.registry import register_rule


@register_rule(name="seven_zip_probe", layer="confirmation")
class SevenZipProbeConfirmationRule(RuleBase):
    required_facts = {"7z.probe"}
    produced_facts = {
        "file.container_type",
        "file.probe_detected_archive",
        "file.probe_offset",
        "file.detected_ext",
    }
    config_schema = {
        "score_min": {
            "type": "int",
            "required": False,
            "description": "Minimum scoring-layer score for this confirmation rule to run.",
        },
        "score_max": {
            "type": "int",
            "required": False,
            "description": "Maximum scoring-layer score for this confirmation rule to run.",
        },
        "reject_executable_container": {
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Reject when 7-Zip identifies a plain executable container.",
        },
        "reject_clear_non_archive": {
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Reject when 7-Zip clearly does not identify an archive.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> ConfirmationEffect:
        probe = facts.get("7z.probe")
        if not probe or probe.get("error"):
            return ConfirmationEffect.pass_()

        probe_type = probe.get("type")
        if probe_type in {"pe", "elf", "macho", "te"}:
            facts.set("file.container_type", probe_type)
            if config.get("reject_executable_container", False):
                return ConfirmationEffect.reject(f"7z probe identified executable container {probe_type}")
            return ConfirmationEffect.pass_()

        if probe.get("is_archive"):
            facts.set("file.probe_detected_archive", True)
            probe_offset = int(probe.get("offset") or 0)
            existing_offset = int(facts.get("file.probe_offset") or 0)
            facts.set("file.probe_offset", max(existing_offset, probe_offset))
            if probe_type:
                detected_ext = f".{probe_type}" if not probe_type.startswith(".") else probe_type
                if not facts.has("file.detected_ext"):
                    facts.set("file.detected_ext", detected_ext)
            return ConfirmationEffect.confirm("7z probe identified archive")

        if probe.get("is_encrypted") or probe.get("is_broken"):
            return ConfirmationEffect.confirm("7z probe found archive-like encrypted/broken structure")

        if config.get("reject_clear_non_archive", True):
            return ConfirmationEffect.reject("7z probe did not identify archive")
        return ConfirmationEffect.pass_()
