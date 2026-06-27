from typing import Any, Dict

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import ConfirmationEffect
from sunpack.detection.pipeline.rules.base import RuleBase
from sunpack.detection.pipeline.rules.registry import register_rule


@register_rule("executable_carrier_policy", "confirmation")
class ExecutableCarrierPolicyRule(RuleBase):
    required_facts = {"executable.carrier"}
    produced_facts = {"file.container_type"}
    config_schema = {
        "always_run": {
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Run this safety policy even when scoring already reached the archive threshold.",
        },
        "reject_runtime_bundles": {
            "type": "bool",
            "required": False,
            "default": True,
            "description": "Reject executable application runtime bundles while retaining SFX archive candidates.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> ConfirmationEffect:
        carrier = facts.get("executable.carrier") or {}
        if not carrier.get("is_executable"):
            return ConfirmationEffect.pass_()

        facts.set("file.container_type", "pe")
        if carrier.get("kind") == "runtime_bundle" and config.get("reject_runtime_bundles", True):
            profile = str(carrier.get("runtime_profile") or "application runtime packer")
            return ConfirmationEffect.reject(
                f"Executable carrier is an application runtime bundle ({profile}), not an auto-extract SFX archive"
            )

        # Known SFX and structurally proven but unknown executable archives pass
        # through to the remaining archive/encryption/damage confirmations.
        return ConfirmationEffect.pass_()
