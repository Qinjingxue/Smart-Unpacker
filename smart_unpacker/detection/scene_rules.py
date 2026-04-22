from __future__ import annotations

import os

from smart_unpacker.support.types import FileRelation, InspectionResult, SceneContext


class SceneAnalyzer:
    RESOURCE_DIR_PREFIXES = (
        "www/audio",
        "www/data",
        "www/fonts",
        "www/icon",
        "www/img",
        "www/js",
        "www/movies",
        "www/save",
        "locales",
        "swiftshader",
    )

    def __init__(self, engine):
        self.engine = engine
        self.scene_context_cache: dict[str, SceneContext] = {}

    def clear_caches(self) -> None:
        self.scene_context_cache.clear()

    def _normalize_relpath(self, rel_path):
        if rel_path is None:
            return ""
        return rel_path.replace("\\", "/").strip("./")

    def _is_under_prefix(self, rel_path, prefixes):
        return any(rel_path == prefix or rel_path.startswith(prefix + "/") for prefix in prefixes)

    def detect_scene_context(self, target_dir):
        norm_target = os.path.normpath(target_dir)
        cached = self.scene_context_cache.get(norm_target)
        if cached is not None and cached.scene_type != "generic":
            return cached

        entries = set()
        try:
            entries = {name.lower() for name in os.listdir(norm_target)}
        except Exception:
            pass

        markers = set()
        if "www" in entries:
            markers.add("www_dir")
        if "game.exe" in entries:
            markers.add("game_exe")
        if "package.json" in entries:
            markers.add("package_json")
        if "locales" in entries:
            markers.add("locales_dir")

        extra_checks = (
            ("www/js/rpg_core.js", "rpg_core"),
            ("www/js/rpg_managers.js", "rpg_managers"),
            ("www/js/plugins.js", "plugins_js"),
            ("www/data", "data_dir"),
        )
        for rel_path, marker in extra_checks:
            if os.path.exists(os.path.join(norm_target, *rel_path.split("/"))):
                markers.add(marker)

        is_rpg_maker_game = (
            "www_dir" in markers
            and (
                "game_exe" in markers
                or "package_json" in markers
                or "rpg_core" in markers
                or "rpg_managers" in markers
            )
        )

        context = SceneContext(
            target_dir=norm_target,
            scene_type="rpg_maker_game" if is_rpg_maker_game else "generic",
            markers=markers,
        )
        self.scene_context_cache[norm_target] = context
        return context

    def resolve_scene_context_for_path(self, current_dir, scan_root):
        norm_current = os.path.normpath(current_dir)
        norm_scan_root = os.path.normpath(scan_root)
        current = norm_current
        fallback = self.detect_scene_context(norm_scan_root)

        while True:
            context = self.detect_scene_context(current)
            if context.scene_type != "generic":
                return context
            if os.path.normcase(current) == os.path.normcase(norm_scan_root):
                return fallback
            parent = os.path.dirname(current)
            if not parent or os.path.normcase(parent) == os.path.normcase(current):
                return fallback
            current = parent

    def classify_scene_role(self, relation: FileRelation, scene_context: SceneContext):
        rel_path = self._normalize_relpath(relation.relative_path)
        scene_root = scene_context.target_dir if scene_context else None
        if scene_root and relation.path:
            safe_rel = self.engine._safe_relpath(relation.path, scene_root)
            if safe_rel is not None:
                rel_path = self._normalize_relpath(safe_rel)

        ext = relation.ext.lower()

        if scene_context and scene_context.scene_type == "rpg_maker_game":
            if self._is_under_prefix(rel_path, self.RESOURCE_DIR_PREFIXES):
                if ext in self.engine.STANDARD_EXTS or ext == ".exe" or relation.is_split_related:
                    return "embedded_resource_archive"
                if ext in self.engine.STRICT_SEMANTIC_SKIP_EXTS or ext in self.engine.LIKELY_RESOURCE_EXTS:
                    return "embedded_resource"

            if rel_path in {"game.exe", "package.json"}:
                return "game_runtime"

        return "generic"

    def apply_scene_semantics(self, info: InspectionResult, relation: FileRelation | None, scene_context: SceneContext | None):
        if not relation or not scene_context:
            return

        role = self.classify_scene_role(relation, scene_context)
        info.scene_role = role
        if role == "embedded_resource_archive":
            info.score -= 8
            info.reasons.append("-8 目录语义保护：游戏资源目录中的归档型资源，默认不继续解压")
        elif role == "embedded_resource":
            info.score -= 4
            info.reasons.append("-4 目录语义保护：游戏资源目录中的常规资源")
