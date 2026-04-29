from typing import Any, Dict

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import ConfirmationEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


@register_rule(name="seven_zip_validation", layer="confirmation")
class SevenZipValidationConfirmationRule(RuleBase):
    required_facts = {"7z.validation"}
    produced_facts = {"file.validation_ok", "file.validation_encrypted"}
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
        "reject_on_failed": {
            "type": "bool",
            "required": False,
            "default": False,
            "description": "Reject when 7-Zip validation fails without encryption.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> ConfirmationEffect:
        validation = facts.get("7z.validation")
        if not validation or validation.get("error"):
            return ConfirmationEffect.pass_()

        if validation.get("is_executable_container"):
            return ConfirmationEffect.pass_()

        if validation.get("checksum_error") and facts.get("file.container_type") in {"pe", "elf", "macho", "te"}:
            return ConfirmationEffect.pass_()

        if validation.get("ok"):
            facts.set("file.validation_ok", True)
            return ConfirmationEffect.confirm("7z test passed")

        if validation.get("encrypted"):
            facts.set("file.validation_encrypted", True)
            return ConfirmationEffect.confirm("7z test encountered encrypted archive")

        if config.get("reject_on_failed", False):
            return ConfirmationEffect.reject("7z test failed")
        return ConfirmationEffect.pass_()
