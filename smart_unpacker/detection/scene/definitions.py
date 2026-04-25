from typing import Any, Dict, List


RECOMMENDED_SCENE_RULES_PAYLOAD: List[Dict[str, Any]] = [
    {
        "scene_type": "rpg_maker_game",
        "display_name": "RPG Maker",
        "top_level_dir_markers": {"www": "www_dir", "locales": "locales_dir", "swiftshader": "swiftshader_dir"},
        "top_level_file_markers": {"game.exe": "game_exe", "package.json": "package_json"},
        "nested_path_markers": {
            "www/js/rpg_core.js": "rpg_core",
            "www/js/rpg_managers.js": "rpg_managers",
            "www/js/plugins.js": "plugins_js",
            "www/data": "data_dir",
        },
        "match_variants": [
            {"all_of": ["www_dir"], "any_of": ["game_exe", "package_json", "rpg_core", "rpg_managers", "plugins_js", "data_dir"]},
        ],
        "weak_match_variants": [
            {"all_of": ["www_dir"], "any_of": ["js_dir", "data_dir", "img_dir", "audio_dir", "fonts_dir", "runtime_exe"]},
            {"all_of": ["www_dir", "js_dir", "data_dir"], "any_of": []},
        ],
        "protected_prefixes": [
            "www/audio", "www/data", "www/fonts", "www/icon", "www/img", "www/js",
            "www/movies", "www/save", "locales", "swiftshader",
        ],
        "protected_exact_paths": [],
        "protected_archive_exts": [".7z", ".rar", ".zip", ".gz", ".bz2", ".xz", ".exe"],
        "runtime_exact_paths": ["game.exe", "package.json"],
    },
    {
        "scene_type": "renpy_game",
        "display_name": "Ren'Py",
        "top_level_dir_markers": {"game": "game_dir", "renpy": "renpy_dir", "lib": "lib_dir"},
        "top_level_file_markers": {},
        "top_level_glob_markers": [["*.rpa", "rpa_archive"]],
        "nested_path_markers": {
            "game/options.rpy": "options_rpy",
            "game/script.rpy": "script_rpy",
            "game/script.rpyc": "script_rpyc",
        },
        "match_variants": [
            {"all_of": ["game_dir"], "any_of": ["renpy_dir", "lib_dir", "rpa_archive", "options_rpy", "script_rpy", "script_rpyc"]},
        ],
        "weak_match_variants": [
            {"all_of": ["game_dir"], "any_of": ["renpy_dir", "lib_dir", "script_rpy", "script_rpyc"]},
            {"all_of": ["game_dir", "script_rpy"], "any_of": []},
        ],
        "protected_prefixes": ["game", "renpy"],
        "protected_exact_paths": [],
        "protected_archive_exts": [".rpa", ".zip", ".7z", ".rar", ".001", ".exe"],
        "runtime_exact_paths": ["game/options.rpy", "game/script.rpy", "game/script.rpyc"],
    },
    {
        "scene_type": "godot_game",
        "display_name": "Godot",
        "top_level_dir_markers": {"packs": "packs_dir", "dlc": "dlc_dir", "mods": "mods_dir", "content": "content_dir", "patches": "patches_dir"},
        "top_level_file_markers": {"data.pck": "data_pck", "project.godot": "project_godot"},
        "top_level_glob_markers": [["*.pck", "pck_pack"], ["*.exe", "runtime_exe"]],
        "nested_path_markers": {},
        "match_variants": [
            {"all_of": ["runtime_exe", "data_pck"], "any_of": []},
            {"all_of": ["project_godot"], "any_of": []},
            {"all_of": ["runtime_exe", "pck_pack"], "any_of": []},
        ],
        "weak_match_variants": [
            {"all_of": ["runtime_exe"], "any_of": ["packs_dir", "dlc_dir", "mods_dir", "content_dir", "patches_dir"]},
            {"all_of": ["pck_pack"], "any_of": ["packs_dir", "dlc_dir", "mods_dir", "content_dir", "patches_dir"]},
        ],
        "protected_prefixes": ["packs", "dlc", "mods", "content", "patches"],
        "protected_exact_paths": ["data.pck"],
        "protected_archive_exts": [".pck", ".zip"],
        "runtime_exact_paths": ["project.godot"],
    },
    {
        "scene_type": "nwjs_game",
        "display_name": "NW.js",
        "top_level_dir_markers": {"package.nw": "package_nw_dir", "locales": "locales_dir"},
        "top_level_file_markers": {
            "nw.exe": "nw_exe",
            "package.nw": "package_nw",
            "nw.pak": "nw_pak",
            "icudtl.dat": "chromium_icudtl",
            "ffmpegsumo.dll": "chromium_ffmpeg",
            "libegl.dll": "chromium_libegl",
            "libglesv2.dll": "chromium_libgles",
        },
        "top_level_glob_markers": [["*.exe", "app_exe"]],
        "nested_path_markers": {"package.nw/package.json": "package_nw_package_json"},
        "match_variants": [
            {"all_of": ["package_nw"], "any_of": ["nw_exe", "app_exe"]},
            {"all_of": ["package_nw_dir", "package_nw_package_json"], "any_of": []},
            {"all_of": ["app_exe", "locales_dir", "nw_pak"], "any_of": ["chromium_icudtl", "chromium_ffmpeg", "chromium_libegl", "chromium_libgles"]},
        ],
        "weak_match_variants": [
            {"all_of": ["package_nw"], "any_of": []},
            {"all_of": ["package_nw_dir"], "any_of": ["package_nw_package_json", "app_exe"]},
            {"all_of": ["app_exe", "nw_pak"], "any_of": ["locales_dir", "chromium_icudtl", "chromium_ffmpeg", "chromium_libegl", "chromium_libgles"]},
        ],
        "protected_prefixes": ["package.nw"],
        "protected_exact_paths": ["package.nw"],
        "protected_archive_exts": [".nw", ".zip", ".exe"],
        "runtime_exact_paths": ["nw.exe"],
    },
    {
        "scene_type": "electron_app_game",
        "display_name": "Electron",
        "top_level_dir_markers": {"resources": "resources_dir"},
        "top_level_file_markers": {},
        "top_level_glob_markers": [["*.exe", "app_exe"]],
        "nested_path_markers": {"resources/app.asar": "app_asar", "resources/app": "resources_app_dir"},
        "match_variants": [
            {"all_of": ["resources_dir", "app_exe"], "any_of": ["app_asar", "resources_app_dir"]},
            {"all_of": ["resources_dir", "app_asar"], "any_of": []},
        ],
        "weak_match_variants": [
            {"all_of": ["resources_dir"], "any_of": ["app_exe", "app_asar", "resources_app_dir"]},
        ],
        "protected_prefixes": ["resources", "resources/app", "resources/app.asar.unpacked"],
        "protected_exact_paths": ["resources/app.asar"],
        "protected_archive_exts": [".asar", ".zip"],
        "runtime_exact_paths": [],
    },
]


def scene_rules(config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    rules = (config or {}).get("scene_rules")
    return rules if isinstance(rules, list) else RECOMMENDED_SCENE_RULES_PAYLOAD
