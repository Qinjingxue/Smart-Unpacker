import os
from typing import Any, Dict

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.rules import RuleEffect
from smart_unpacker.detection.pipeline.rules.base import RuleBase
from smart_unpacker.detection.pipeline.rules.registry import register_rule
from smart_unpacker.detection.scene.definitions import RECOMMENDED_SCENE_RULES_PAYLOAD


DEFAULT_RUNTIME_RESOURCE_ARCHIVE_PENALTY = -99
DEFAULT_WEAK_PROTECTED_PATH_PENALTY = -4
DEFAULT_RESOURCE_PENALTY = -4
DEFAULT_RUNTIME_EXACT_PATH_PENALTY = 0


@register_rule(name="scene_penalty", layer="scoring")
class ScenePenaltyRule(RuleBase):
    required_facts = {
        "scene.context",
        "scene.scene_type",
        "scene.match_strength",
        "scene.is_runtime_exact_path",
        "scene.is_protected_path",
        "scene.is_runtime_resource_archive",
        "file.path",
    }
    fact_requirements = []
    config_schema = {
        "scene_rules": {
            "type": "list[dict]",
            "required": False,
            "default": RECOMMENDED_SCENE_RULES_PAYLOAD,
            "description": "Scene rules used to identify protected runtime resource paths.",
        },
        "runtime_resource_archive_penalty": {
            "type": "int",
            "required": False,
            "default": DEFAULT_RUNTIME_RESOURCE_ARCHIVE_PENALTY,
            "description": "Score applied to protected scene runtime resource archives when hard-stop is disabled.",
        },
        "weak_protected_path_penalty": {
            "type": "int",
            "required": False,
            "default": DEFAULT_WEAK_PROTECTED_PATH_PENALTY,
            "description": "Score applied to candidates in protected paths under weak scene matches.",
        },
        "resource_penalty": {
            "type": "int",
            "required": False,
            "default": DEFAULT_RESOURCE_PENALTY,
            "description": "Score applied to semantic/resource files in protected scene paths.",
        },
        "runtime_exact_path_penalty": {
            "type": "int",
            "required": False,
            "default": DEFAULT_RUNTIME_EXACT_PATH_PENALTY,
            "description": "Score applied to exact runtime marker paths.",
        },
        "semantic_resource_exts": {
            "type": "list[str]",
            "required": True,
            "description": "Extensions considered strong semantic resources.",
        },
        "likely_resource_exts": {
            "type": "list[str]",
            "required": True,
            "description": "Complete resource extension set for scene penalties.",
        },
        "scene_context_max_parent_depth": {
            "type": "int",
            "required": False,
            "description": "Maximum number of parent directories searched when collecting scene facts.",
        },
    }

    def _normalized_exts(self, values) -> set[str]:
        normalized = set()
        for value in values or []:
            if not isinstance(value, str) or not value.strip():
                continue
            ext = value.strip().lower()
            normalized.add(ext if ext.startswith(".") else f".{ext}")
        return normalized

    def _is_resource_ext(self, ext: str, config: Dict[str, Any]) -> bool:
        semantic_exts = self._normalized_exts(config.get("semantic_resource_exts"))
        resource_exts = self._normalized_exts(config.get("likely_resource_exts"))
        return ext in semantic_exts or ext in resource_exts

    def evaluate(self, facts: FactBag, config: Dict[str, Any]) -> RuleEffect:
        scene_type = facts.get("scene.scene_type") or "generic"
        if scene_type == "generic":
            return RuleEffect.pass_()

        if facts.get("scene.is_runtime_resource_archive"):
            return RuleEffect.add_score(
                config.get("runtime_resource_archive_penalty", DEFAULT_RUNTIME_RESOURCE_ARCHIVE_PENALTY),
                reason=f"Scene Penalty: {scene_type} protected runtime resource archive",
            )

        if facts.get("scene.is_runtime_exact_path"):
            penalty = config.get("runtime_exact_path_penalty", DEFAULT_RUNTIME_EXACT_PATH_PENALTY)
            if penalty:
                return RuleEffect.add_score(penalty, reason=f"Scene Penalty: {scene_type} runtime marker")
            return RuleEffect.pass_()

        if not facts.get("scene.is_protected_path"):
            return RuleEffect.pass_()

        if facts.get("scene.match_strength") == "weak":
            return RuleEffect.add_score(
                config.get("weak_protected_path_penalty", DEFAULT_WEAK_PROTECTED_PATH_PENALTY),
                reason=f"Scene Penalty: {scene_type} weak protected path",
            )

        ext = os.path.splitext(facts.get("file.path") or "")[1].lower()
        if self._is_resource_ext(ext, config):
            return RuleEffect.add_score(
                config.get("resource_penalty", DEFAULT_RESOURCE_PENALTY),
                reason=f"Scene Penalty: {scene_type} runtime embedded resource",
            )

        return RuleEffect.pass_()
