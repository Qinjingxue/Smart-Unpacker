from __future__ import annotations

from copy import deepcopy
from typing import Any

from smart_unpacker.support.types import DetectionConfig, LooseScanConfig


DEFAULT_MIN_INSPECTION_SIZE_BYTES = 1024 * 1024
DEFAULT_ARCHIVE_SCORE_THRESHOLD = 6
DEFAULT_MAYBE_ARCHIVE_THRESHOLD = 3

DEFAULT_MAGIC_SIGNATURES = {
    b"7z\xbc\xaf'\x1c": ".7z",
    b"Rar!": ".rar",
    b"PK\x03\x04": ".zip",
    b"PK\x05\x06": ".zip",
    b"PK\x07\x08": ".zip",
    b"\x1f\x8b": ".gz",
    b"BZh": ".bz2",
    b"\xfd7zXZ\x00": ".xz",
}
DEFAULT_WEAK_MAGIC_SIGNATURES = {
    b"MZ": ".exe",
}
DEFAULT_TAIL_MAGIC_SIGNATURES = {
    b"7z\xbc\xaf'\x1c": ".7z",
    b"Rar!": ".rar",
    b"PK\x03\x04": ".zip",
    b"PK\x05\x06": ".zip",
    b"PK\x07\x08": ".zip",
}

DEFAULT_SPLIT_FIRST_PATTERNS = (
    r"\.part0*1\.rar(?:\.[^.]+)?$",
    r"\.(7z|zip|rar)\.001(?:\.[^.]+)?$",
    r"\.001(?:\.[^.]+)?$",
)
DEFAULT_SPLIT_MEMBER_PATTERN = r"\.(part\d+\.rar|\d{3})(?:\.[^.]+)?$"
DEFAULT_DISGUISED_ARCHIVE_NAME_PATTERNS = (
    r"\.(7z|rar|zip|gz|bz2|xz)\.[^.]+$",
    r"\.exe\.[^.]+$",
    r"\.(7z|zip|rar)\.001(?:\.[^.]+)?$",
    r"\.part\d+\.rar(?:\.[^.]+)?$",
    r"\.\d{3}(?:\.[^.]+)?$",
)

DEFAULT_LOOSE_SCAN = LooseScanConfig(
    stream_chunk_size=1024 * 1024,
    min_prefix=32,
    min_tail_bytes=4 * 1024,
    max_hits=3,
)


RECOMMENDED_EXTENSIONS_PAYLOAD: dict[str, list[str]] = {
    "standard_archive_exts": [".7z", ".rar", ".zip", ".gz", ".bz2", ".xz"],
    "strict_semantic_skip_exts": [
        ".dll", ".save", ".py", ".pyc", ".json", ".xml", ".cfg", ".ini", ".sys", ".db",
        ".msi", ".cur", ".ani", ".ttf", ".woff", ".ico", ".pak", ".obb", ".unitypackage",
        ".jar", ".apk", ".ipa", ".epub", ".odt", ".ods", ".odp", ".docx", ".xlsx",
        ".pptx", ".whl", ".xpi", ".war", ".ear", ".aab",
    ],
    "ambiguous_resource_exts": [".dat", ".bin"],
    "likely_resource_exts_extra": [
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tga",
        ".mp3", ".wav", ".ogg", ".flac", ".aac",
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm",
        ".txt", ".log", ".csv", ".pdf",
    ],
    "carrier_exts": [".jpg", ".jpeg", ".png", ".pdf", ".gif", ".webp"],
}

RECOMMENDED_SCENE_RULES_PAYLOAD: list[dict[str, Any]] = [
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
        "top_level_dir_markers": {"package.nw": "package_nw_dir"},
        "top_level_file_markers": {"nw.exe": "nw_exe", "package.nw": "package_nw"},
        "top_level_glob_markers": [["*.exe", "app_exe"]],
        "nested_path_markers": {"package.nw/package.json": "package_nw_package_json"},
        "match_variants": [
            {"all_of": ["package_nw"], "any_of": ["nw_exe", "app_exe"]},
            {"all_of": ["package_nw_dir", "package_nw_package_json"], "any_of": []},
        ],
        "weak_match_variants": [
            {"all_of": ["package_nw"], "any_of": []},
            {"all_of": ["package_nw_dir"], "any_of": ["package_nw_package_json", "app_exe"]},
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


def build_builtin_detection_config() -> DetectionConfig:
    return DetectionConfig(
        archive_score_threshold=DEFAULT_ARCHIVE_SCORE_THRESHOLD,
        maybe_archive_threshold=DEFAULT_MAYBE_ARCHIVE_THRESHOLD,
        split_first_patterns=DEFAULT_SPLIT_FIRST_PATTERNS,
        split_member_pattern=DEFAULT_SPLIT_MEMBER_PATTERN,
        disguised_archive_name_patterns=DEFAULT_DISGUISED_ARCHIVE_NAME_PATTERNS,
        magic_signatures=dict(DEFAULT_MAGIC_SIGNATURES),
        weak_magic_signatures=dict(DEFAULT_WEAK_MAGIC_SIGNATURES),
        tail_magic_signatures=dict(DEFAULT_TAIL_MAGIC_SIGNATURES),
        loose_scan=DEFAULT_LOOSE_SCAN,
    )


def build_default_config_payload() -> dict[str, Any]:
    return {
        "extraction_rules": {
            "min_inspection_size_bytes": DEFAULT_MIN_INSPECTION_SIZE_BYTES,
            "thresholds": {
                "archive_score_threshold": DEFAULT_ARCHIVE_SCORE_THRESHOLD,
                "maybe_archive_threshold": DEFAULT_MAYBE_ARCHIVE_THRESHOLD,
            },
            "extensions": deepcopy(RECOMMENDED_EXTENSIONS_PAYLOAD),
            "blacklist": {
                "directory_patterns": [],
                "filename_patterns": [],
            },
            "scene_rules": deepcopy(RECOMMENDED_SCENE_RULES_PAYLOAD),
        },
        "post_extract": {
            "archive_cleanup_mode": "recycle",
            "flatten_single_directory": True,
        },
        "recursive_extract": "*",
        "performance": {
            "scheduler_profile": "auto",
            "scheduler": {
                "initial_concurrency_limit": 0,
                "poll_interval_ms": 0,
                "scale_up_threshold_mb_s": 0,
                "scale_up_backlog_threshold_mb_s": 0,
                "scale_down_threshold_mb_s": 0,
                "scale_up_streak_required": 0,
                "scale_down_streak_required": 0,
                "medium_backlog_threshold": 0,
                "high_backlog_threshold": 0,
                "medium_floor_workers": 0,
                "high_floor_workers": 0,
            },
            "max_workers_override": 0,
            "embedded_archive_scan": {
                "stream_chunk_size": DEFAULT_LOOSE_SCAN.stream_chunk_size,
                "min_prefix": DEFAULT_LOOSE_SCAN.min_prefix,
                "min_tail_bytes": DEFAULT_LOOSE_SCAN.min_tail_bytes,
                "max_hits": DEFAULT_LOOSE_SCAN.max_hits,
            },
        },
    }
