from typing import Any

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import ConfirmationEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


@register_rule("executable_carrier_veto", "confirmation")
class ExecutableCarrierVetoRule(RuleBase):
    required_facts = {"executable.carrier"}
    produced_facts = {"file.container_type"}
    config_schema = {
        "always_run": {"type": "bool", "required": False, "default": True},
        "reject_runtime_bundles": {"type": "bool", "required": False, "default": True},
    }

    def evaluate(self, facts: FactBag, config: dict[str, Any]) -> ConfirmationEffect:
        carrier = facts.get("executable.carrier") or {}
        if not carrier.get("is_executable"):
            return ConfirmationEffect.pass_()
        facts.set("file.container_type", "pe")
        if carrier.get("kind") == "runtime_bundle" and config.get("reject_runtime_bundles", True):
            profile = str(carrier.get("runtime_profile") or "unknown")
            return ConfirmationEffect.reject(
                f"Executable application/installer bundle ({profile}) is not treated as a user archive"
            )
        return ConfirmationEffect.pass_()
