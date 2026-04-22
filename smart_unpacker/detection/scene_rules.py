from __future__ import annotations

import os
from fnmatch import fnmatch

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
    SCENE_RULES = (
        {
            "scene_type": "rpg_maker_game",
            "display_name": "RPG Maker",
            "top_level_dir_markers": {
                "www": "www_dir",
                "locales": "locales_dir",
                "swiftshader": "swiftshader_dir",
            },
            "top_level_file_markers": {
                "game.exe": "game_exe",
                "package.json": "package_json",
            },
            "nested_path_markers": {
                "www/js/rpg_core.js": "rpg_core",
                "www/js/rpg_managers.js": "rpg_managers",
                "www/js/plugins.js": "plugins_js",
                "www/data": "data_dir",
            },
            "match_variants": (
                {"all_of": {"www_dir"}, "any_of": {"game_exe", "package_json", "rpg_core", "rpg_managers", "plugins_js", "data_dir"}},
            ),
            "protected_prefixes": RESOURCE_DIR_PREFIXES,
            "protected_exact_paths": (),
            "protected_archive_exts": {".7z", ".rar", ".zip", ".gz", ".bz2", ".xz", ".exe"},
            "runtime_exact_paths": {"game.exe", "package.json"},
        },
        {
            "scene_type": "renpy_game",
            "display_name": "Ren'Py",
            "top_level_dir_markers": {
                "game": "game_dir",
                "renpy": "renpy_dir",
                "lib": "lib_dir",
            },
            "top_level_file_markers": {},
            "top_level_glob_markers": (
                ("*.rpa", "rpa_archive"),
            ),
            "nested_path_markers": {
                "game/options.rpy": "options_rpy",
                "game/script.rpy": "script_rpy",
                "game/script.rpyc": "script_rpyc",
            },
            "match_variants": (
                {"all_of": {"game_dir"}, "any_of": {"renpy_dir", "lib_dir", "rpa_archive", "options_rpy", "script_rpy", "script_rpyc"}},
            ),
            "protected_prefixes": ("game", "renpy"),
            "protected_exact_paths": (),
            "protected_archive_exts": {".rpa", ".zip", ".7z", ".rar", ".001", ".exe"},
            "runtime_exact_paths": {"game/options.rpy", "game/script.rpy", "game/script.rpyc"},
        },
        {
            "scene_type": "godot_game",
            "display_name": "Godot",
            "top_level_dir_markers": {
                "packs": "packs_dir",
                "dlc": "dlc_dir",
                "mods": "mods_dir",
                "content": "content_dir",
                "patches": "patches_dir",
            },
            "top_level_file_markers": {
                "data.pck": "data_pck",
                "project.godot": "project_godot",
            },
            "top_level_glob_markers": (
                ("*.pck", "pck_pack"),
                ("*.exe", "runtime_exe"),
            ),
            "nested_path_markers": {},
            "match_variants": (
                {"all_of": {"runtime_exe", "data_pck"}, "any_of": set()},
                {"all_of": {"project_godot"}, "any_of": set()},
                {"all_of": {"runtime_exe", "pck_pack"}, "any_of": set()},
            ),
            "protected_prefixes": ("packs", "dlc", "mods", "content", "patches"),
            "protected_exact_paths": {"data.pck"},
            "protected_archive_exts": {".pck", ".zip"},
            "runtime_exact_paths": {"project.godot"},
        },
        {
            "scene_type": "nwjs_game",
            "display_name": "NW.js",
            "top_level_dir_markers": {
                "package.nw": "package_nw_dir",
            },
            "top_level_file_markers": {
                "nw.exe": "nw_exe",
                "package.nw": "package_nw",
            },
            "top_level_glob_markers": (
                ("*.exe", "app_exe"),
            ),
            "nested_path_markers": {
                "package.nw/package.json": "package_nw_package_json",
            },
            "match_variants": (
                {"all_of": {"package_nw"}, "any_of": {"nw_exe", "app_exe"}},
                {"all_of": {"package_nw_dir", "package_nw_package_json"}, "any_of": set()},
            ),
            "protected_prefixes": ("package.nw",),
            "protected_exact_paths": {"package.nw"},
            "protected_archive_exts": {".nw", ".zip", ".exe"},
            "runtime_exact_paths": {"nw.exe"},
        },
        {
            "scene_type": "electron_app_game",
            "display_name": "Electron",
            "top_level_dir_markers": {
                "resources": "resources_dir",
            },
            "top_level_file_markers": {},
            "top_level_glob_markers": (
                ("*.exe", "app_exe"),
            ),
            "nested_path_markers": {
                "resources/app.asar": "app_asar",
                "resources/app": "resources_app_dir",
            },
            "match_variants": (
                {"all_of": {"resources_dir", "app_exe"}, "any_of": {"app_asar", "resources_app_dir"}},
                {"all_of": {"resources_dir", "app_asar"}, "any_of": set()},
            ),
            "protected_prefixes": ("resources", "resources/app", "resources/app.asar.unpacked"),
            "protected_exact_paths": {"resources/app.asar"},
            "protected_archive_exts": {".asar", ".zip"},
            "runtime_exact_paths": (),
        },
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

    def _collect_scene_markers(self, norm_target: str) -> set[str]:
        markers = set()
        try:
            entries = list(os.scandir(norm_target))
        except Exception:
            return markers

        for rule in self.SCENE_RULES:
            for entry in entries:
                name_lower = entry.name.lower()
                if entry.is_dir() and name_lower in rule.get("top_level_dir_markers", {}):
                    markers.add(rule["top_level_dir_markers"][name_lower])
                if entry.is_file() and name_lower in rule.get("top_level_file_markers", {}):
                    markers.add(rule["top_level_file_markers"][name_lower])
                for pattern, marker in rule.get("top_level_glob_markers", ()):
                    if fnmatch(name_lower, pattern):
                        markers.add(marker)

            for rel_path, marker in rule.get("nested_path_markers", {}).items():
                if os.path.exists(os.path.join(norm_target, *rel_path.split("/"))):
                    markers.add(marker)

        return markers

    @staticmethod
    def _variant_matches(markers: set[str], variant: dict) -> bool:
        all_of = set(variant.get("all_of", set()))
        any_of = set(variant.get("any_of", set()))
        if all_of and not all_of.issubset(markers):
            return False
        if any_of and not (markers & any_of):
            return False
        return True

    def _match_scene_rule(self, markers: set[str]):
        for rule in self.SCENE_RULES:
            for variant in rule.get("match_variants", ()):
                if self._variant_matches(markers, variant):
                    return rule
        return None

    def _get_scene_rule(self, scene_type: str):
        for rule in self.SCENE_RULES:
            if rule["scene_type"] == scene_type:
                return rule
        return None

    def _matches_protected_location(self, rel_path: str, rule: dict) -> bool:
        if rel_path in rule.get("protected_exact_paths", set()):
            return True
        return self._is_under_prefix(rel_path, rule.get("protected_prefixes", ()))

    def detect_scene_context(self, target_dir):
        norm_target = os.path.normpath(target_dir)
        cached = self.scene_context_cache.get(norm_target)
        if cached is not None:
            return cached

        markers = self._collect_scene_markers(norm_target)
        matched_rule = self._match_scene_rule(markers)

        context = SceneContext(
            target_dir=norm_target,
            scene_type=matched_rule["scene_type"] if matched_rule else "generic",
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
        if not scene_context or scene_context.scene_type == "generic":
            return "generic"

        rule = self._get_scene_rule(scene_context.scene_type)
        if not rule:
            return "generic"

        if rel_path in rule.get("runtime_exact_paths", set()):
            return "game_runtime"

        if self._matches_protected_location(rel_path, rule):
            if ext in rule.get("protected_archive_exts", set()) or relation.is_split_related:
                return "embedded_resource_archive"
            if ext in self.engine.STRICT_SEMANTIC_SKIP_EXTS or ext in self.engine.LIKELY_RESOURCE_EXTS:
                return "embedded_resource"

        return "generic"

    def apply_scene_semantics(self, info: InspectionResult, relation: FileRelation | None, scene_context: SceneContext | None):
        if not relation or not scene_context:
            return

        role = self.classify_scene_role(relation, scene_context)
        info.scene_role = role
        rule = self._get_scene_rule(scene_context.scene_type)
        scene_label = rule["display_name"] if rule else scene_context.scene_type
        if role == "embedded_resource_archive":
            info.score -= 8
            info.reasons.append("-8 目录语义保护：识别为游戏运行时资源包，默认不继续解压")
            info.reasons.append(f"+0 场景识别：{scene_label} 运行目录")
        elif role == "embedded_resource":
            info.score -= 4
            info.reasons.append("-4 目录语义保护：游戏运行时资源目录中的常规资源")
            info.reasons.append(f"+0 场景识别：{scene_label} 运行目录")
