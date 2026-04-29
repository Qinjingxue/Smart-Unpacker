from typing import Any, Dict

from packrelic.contracts.detection import FactBag
from packrelic.contracts.rules import RuleEffect
from packrelic.detection.pipeline.rules.base import RuleBase
from packrelic.detection.pipeline.rules.registry import register_rule
from packrelic.detection.scene.definitions import RECOMMENDED_SCENE_RULES_PAYLOAD


@register_rule(name="scene_protect", layer="precheck")
class SceneProtectRule(RuleBase):
    required_facts = {
        "scene.context",
        "scene.scene_type",
        "scene.match_strength",
        "scene.is_runtime_resource_archive",
    }
    config_schema = {
        "scene_rules": {
            "type": "list[dict]",
            "required": False,
            "default": RECOMMENDED_SCENE_RULES_PAYLOAD,
            "description": "Scene protection rules used to protect runtime resource directories.",
        },
        "protect_weak_matches": {
            "type": "bool",
            "required": False,
            "description": "Whether weak scene matches can reject protected runtime resource archives.",
        },
        "scene_context_max_parent_depth": {
            "type": "int",
            "required": False,
            "description": "Maximum number of parent directories searched when collecting scene facts.",
        },
    }

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        if not facts.get("scene.is_runtime_resource_archive"):
            return RuleEffect.pass_()

        match_strength = facts.get("scene.match_strength") or "none"
        if match_strength == "weak" and not config.get("protect_weak_matches"):
            return RuleEffect.pass_()

        scene_type = facts.get("scene.scene_type") or "generic"
        return RuleEffect.reject(
            reason=f"Scene Protect: {scene_type} runtime resource archive ({match_strength} match)"
        )
