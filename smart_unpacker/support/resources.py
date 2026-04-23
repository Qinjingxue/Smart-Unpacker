from __future__ import annotations

import json
import os
import re
import sys

import psutil

from smart_unpacker.detection.defaults import (
    DEFAULT_LOOSE_SCAN,
    DEFAULT_MIN_INSPECTION_SIZE_BYTES,
    build_builtin_detection_config,
    build_default_config_payload,
)
from smart_unpacker.support.types import (
    AppConfig,
    BlacklistConfig,
    DetectionConfig,
    LooseScanConfig,
    PostExtractConfig,
    RecursiveExtractConfig,
)


class ResourceLocator:
    SCHEDULER_PROFILES = {"auto", "conservative", "aggressive"}
    ARCHIVE_CLEANUP_MODES = {"keep", "recycle", "delete"}

    def _coerce_non_negative_int(self, value, default: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed >= 0 else default

    def _coerce_positive_int(self, value, default: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed > 0 else default

    def _coerce_bool(self, value, default: bool) -> bool:
        return value if isinstance(value, bool) else default

    def _coerce_scheduler_profile(self, value, default: str) -> str:
        if not isinstance(value, str):
            return default
        normalized = value.strip().lower()
        return normalized if normalized in self.SCHEDULER_PROFILES else default

    def _coerce_archive_cleanup_mode(self, value, default: str = "recycle") -> str:
        if not isinstance(value, str):
            return default
        normalized = value.strip().lower()
        return normalized if normalized in self.ARCHIVE_CLEANUP_MODES else default

    def _coerce_recursive_extract(self, value) -> RecursiveExtractConfig:
        if isinstance(value, int) and value > 0:
            return RecursiveExtractConfig(mode="fixed", max_rounds=value)
        if isinstance(value, str):
            normalized = value.strip()
            if normalized.isdigit() and int(normalized) > 0:
                return RecursiveExtractConfig(mode="fixed", max_rounds=int(normalized))
            if normalized == "?":
                return RecursiveExtractConfig(mode="prompt", max_rounds=0)
            if normalized == "*":
                return RecursiveExtractConfig(mode="infinite", max_rounds=0)
        return RecursiveExtractConfig(mode="infinite", max_rounds=0)

    def _select_auto_scheduler_profile(self) -> str:
        cpu_count = os.cpu_count() or 4
        memory_gb = 0.0
        try:
            memory_gb = psutil.virtual_memory().total / (1024 ** 3)
        except Exception:
            memory_gb = 0.0
        if cpu_count >= 12 and memory_gb >= 24:
            return "aggressive"
        return "conservative"

    def _build_scheduler_profile_defaults(self, requested_profile: str) -> dict[str, int | str]:
        resolved_profile = requested_profile
        if requested_profile == "auto":
            resolved_profile = self._select_auto_scheduler_profile()

        conservative = {
            "scheduler_profile": requested_profile,
            "initial_concurrency_limit": 4,
            "scheduler_poll_interval_ms": 1000,
            "scheduler_scale_up_threshold_mb_s": 20,
            "scheduler_scale_up_backlog_threshold_mb_s": 40,
            "scheduler_scale_down_threshold_mb_s": 140,
            "scheduler_scale_up_streak_required": 2,
            "scheduler_scale_down_streak_required": 3,
            "scheduler_medium_backlog_threshold": 8,
            "scheduler_high_backlog_threshold": 24,
            "scheduler_medium_floor_workers": 2,
            "scheduler_high_floor_workers": 3,
        }
        aggressive = {
            "scheduler_profile": requested_profile,
            "initial_concurrency_limit": 6,
            "scheduler_poll_interval_ms": 500,
            "scheduler_scale_up_threshold_mb_s": 80,
            "scheduler_scale_up_backlog_threshold_mb_s": 160,
            "scheduler_scale_down_threshold_mb_s": 400,
            "scheduler_scale_up_streak_required": 2,
            "scheduler_scale_down_streak_required": 3,
            "scheduler_medium_backlog_threshold": 8,
            "scheduler_high_backlog_threshold": 24,
            "scheduler_medium_floor_workers": 4,
            "scheduler_high_floor_workers": 6,
        }
        return dict({"conservative": conservative, "aggressive": aggressive}.get(resolved_profile, conservative))

    def _resolve_positive_override(self, raw: dict, key: str, current: int) -> int:
        if key not in raw:
            return current
        return self._coerce_positive_int(raw.get(key), current)

    def _get_dict(self, value) -> dict:
        return value if isinstance(value, dict) else {}

    def _normalize_ext(self, value) -> str | None:
        if not isinstance(value, str):
            return None
        ext = value.strip().lower()
        if not ext:
            return None
        return ext if ext.startswith(".") else "." + ext

    def _coerce_ext_set(self, value) -> set[str]:
        if not isinstance(value, list):
            return set()
        return {ext for item in value if (ext := self._normalize_ext(item))}

    def _coerce_regex_tuple(self, value, default: tuple[str, ...]) -> tuple[str, ...]:
        parsed = []
        if isinstance(value, list):
            for item in value:
                if not isinstance(item, str) or not item.strip():
                    continue
                try:
                    re.compile(item, re.I)
                except re.error:
                    continue
                parsed.append(item.strip())
        return tuple(parsed) if parsed else tuple(default)

    def _coerce_external_regex_tuple(self, value) -> tuple[str, ...]:
        parsed = []
        if not isinstance(value, list):
            return ()
        for item in value:
            if not isinstance(item, str) or not item.strip():
                continue
            normalized = item.strip()
            try:
                re.compile(normalized, re.I)
            except re.error:
                continue
            parsed.append(normalized)
        return tuple(parsed)

    def _coerce_regex(self, value, default: str) -> str:
        if not isinstance(value, str) or not value.strip():
            return default
        try:
            re.compile(value, re.I)
        except re.error:
            return default
        return value

    def _coerce_str_map(self, value) -> dict[str, str]:
        if not isinstance(value, dict):
            return {}
        return {
            str(key).strip().lower(): str(val).strip()
            for key, val in value.items()
            if str(key).strip() and str(val).strip()
        }

    def _coerce_str_list(self, value) -> list[str]:
        if not isinstance(value, list):
            return []
        return [item.strip().lower() for item in value if isinstance(item, str) and item.strip()]

    def _coerce_glob_markers(self, value) -> list[list[str]]:
        if not isinstance(value, list):
            return []
        parsed = []
        for item in value:
            if not isinstance(item, list) or len(item) != 2:
                continue
            pattern, marker = item
            if isinstance(pattern, str) and pattern.strip() and isinstance(marker, str) and marker.strip():
                parsed.append([pattern.strip().lower(), marker.strip()])
        return parsed

    def _coerce_scene_variants(self, value) -> list[dict[str, list[str]]]:
        if not isinstance(value, list):
            return []
        parsed = []
        for item in value:
            if not isinstance(item, dict):
                continue
            parsed.append(
                {
                    "all_of": [marker for marker in item.get("all_of", []) if isinstance(marker, str) and marker.strip()],
                    "any_of": [marker for marker in item.get("any_of", []) if isinstance(marker, str) and marker.strip()],
                }
            )
        return parsed

    def _normalize_scene_rule(self, item: dict) -> dict | None:
        scene_type = item.get("scene_type")
        if not isinstance(scene_type, str) or not scene_type.strip():
            return None
        return {
            "scene_type": scene_type.strip(),
            "display_name": item.get("display_name") if isinstance(item.get("display_name"), str) else scene_type.strip(),
            "top_level_dir_markers": self._coerce_str_map(item.get("top_level_dir_markers")),
            "top_level_file_markers": self._coerce_str_map(item.get("top_level_file_markers")),
            "top_level_glob_markers": self._coerce_glob_markers(item.get("top_level_glob_markers")),
            "nested_path_markers": self._coerce_str_map(item.get("nested_path_markers")),
            "match_variants": self._coerce_scene_variants(item.get("match_variants")),
            "weak_match_variants": self._coerce_scene_variants(item.get("weak_match_variants")),
            "protected_prefixes": self._coerce_str_list(item.get("protected_prefixes")),
            "protected_exact_paths": self._coerce_str_list(item.get("protected_exact_paths")),
            "protected_archive_exts": list(self._coerce_ext_set(item.get("protected_archive_exts"))),
            "runtime_exact_paths": self._coerce_str_list(item.get("runtime_exact_paths")),
        }

    def _coerce_scene_rules(self, value) -> list[dict]:
        if not isinstance(value, list):
            return []
        parsed = []
        for item in value:
            if isinstance(item, dict) and (rule := self._normalize_scene_rule(item)):
                parsed.append(rule)
        return parsed

    def _build_detection_config(self, extraction_rules: dict, performance: dict) -> DetectionConfig:
        builtin = build_builtin_detection_config()
        thresholds = self._get_dict(extraction_rules.get("thresholds"))
        extensions = self._get_dict(extraction_rules.get("extensions"))
        blacklist = self._get_dict(extraction_rules.get("blacklist"))
        embedded_scan = self._get_dict(performance.get("embedded_archive_scan"))
        return DetectionConfig(
            standard_archive_exts=self._coerce_ext_set(extensions.get("standard_archive_exts")),
            strict_semantic_skip_exts=self._coerce_ext_set(extensions.get("strict_semantic_skip_exts")),
            ambiguous_resource_exts=self._coerce_ext_set(extensions.get("ambiguous_resource_exts")),
            likely_resource_exts_extra=self._coerce_ext_set(extensions.get("likely_resource_exts_extra")),
            carrier_exts=self._coerce_ext_set(extensions.get("carrier_exts")),
            archive_score_threshold=self._coerce_positive_int(
                thresholds.get("archive_score_threshold"),
                builtin.archive_score_threshold,
            ),
            maybe_archive_threshold=self._coerce_non_negative_int(
                thresholds.get("maybe_archive_threshold"),
                builtin.maybe_archive_threshold,
            ),
            split_first_patterns=builtin.split_first_patterns,
            split_member_pattern=builtin.split_member_pattern,
            disguised_archive_name_patterns=builtin.disguised_archive_name_patterns,
            magic_signatures=dict(builtin.magic_signatures),
            weak_magic_signatures=dict(builtin.weak_magic_signatures),
            tail_magic_signatures=dict(builtin.tail_magic_signatures),
            loose_scan=LooseScanConfig(
                stream_chunk_size=self._coerce_positive_int(
                    embedded_scan.get("stream_chunk_size"),
                    DEFAULT_LOOSE_SCAN.stream_chunk_size,
                ),
                min_prefix=self._coerce_non_negative_int(
                    embedded_scan.get("min_prefix"),
                    DEFAULT_LOOSE_SCAN.min_prefix,
                ),
                min_tail_bytes=self._coerce_positive_int(
                    embedded_scan.get("min_tail_bytes"),
                    DEFAULT_LOOSE_SCAN.min_tail_bytes,
                ),
                max_hits=self._coerce_positive_int(
                    embedded_scan.get("max_hits"),
                    DEFAULT_LOOSE_SCAN.max_hits,
                ),
            ),
            scene_rules=self._coerce_scene_rules(extraction_rules.get("scene_rules")),
            blacklist=BlacklistConfig(
                directory_patterns=self._coerce_external_regex_tuple(blacklist.get("directory_patterns")),
                filename_patterns=self._coerce_external_regex_tuple(blacklist.get("filename_patterns")),
            ),
        )

    def get_embedded_resource_base_path(self) -> str:
        return getattr(sys, "_MEIPASS", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

    def get_runtime_resource_base_path(self) -> str:
        if getattr(sys, "frozen", False):
            return os.path.dirname(os.path.abspath(sys.executable))
        return self.get_embedded_resource_base_path()

    def get_resource_base_path(self) -> str:
        return self.get_runtime_resource_base_path()

    def get_resource_path(self, *relative_parts: str) -> str:
        return os.path.join(self.get_resource_base_path(), *relative_parts)

    def get_embedded_resource_path(self, *relative_parts: str) -> str:
        return os.path.join(self.get_embedded_resource_base_path(), *relative_parts)

    def find_existing_resource_path(self, *relative_parts: str) -> str | None:
        candidates = [self.get_resource_path(*relative_parts)]
        embedded_candidate = self.get_embedded_resource_path(*relative_parts)
        if embedded_candidate not in candidates:
            candidates.append(embedded_candidate)
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate
        return None

    def find_seven_zip_path(self) -> str:
        candidates = [
            self.get_resource_path("tools", "7z.exe"),
            self.get_resource_path("tools", "7zip", "7z.exe"),
            self.get_embedded_resource_path("tools", "7z.exe"),
            self.get_embedded_resource_path("tools", "7zip", "7z.exe"),
            self.get_resource_path("7z.exe"),
            self.get_embedded_resource_path("7z.exe"),
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate
        return "7z"

    def get_builtin_passwords(self) -> list[str]:
        default_passwords = ["123456", "123", "0000", "789"]
        file_path = self.find_existing_resource_path("builtin_passwords.txt") or self.get_resource_path("builtin_passwords.txt")
        if not os.path.exists(file_path):
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("# 此文件为内置高频密码配置表，用户可自行编辑，每行一个密码。\n")
                    for p in default_passwords:
                        f.write(p + "\n")
            except Exception:
                pass
            return default_passwords

        try:
            from smart_unpacker.support.passwords import read_password_file
            return read_password_file(file_path)
        except Exception:
            return default_passwords

    def get_app_config(self) -> AppConfig:
        default_payload = build_default_config_payload()
        file_path = self.find_existing_resource_path("smart_unpacker_config.json") or self.get_resource_path("smart_unpacker_config.json")
        if not os.path.exists(file_path):
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(default_payload, f, ensure_ascii=False, indent=2)
                    f.write("\n")
            except Exception:
                pass
            raw = default_payload
        else:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            except Exception:
                raw = default_payload

        if not isinstance(raw, dict):
            raw = default_payload

        extraction_rules = self._get_dict(raw.get("extraction_rules"))
        post_extract = self._get_dict(raw.get("post_extract"))
        performance = self._get_dict(raw.get("performance"))

        requested_profile = self._coerce_scheduler_profile(performance.get("scheduler_profile"), "auto")
        scheduler_overrides = self._get_dict(performance.get("scheduler"))
        resolved = self._build_scheduler_profile_defaults(requested_profile)
        resolved["min_inspection_size_bytes"] = self._coerce_non_negative_int(
            extraction_rules.get("min_inspection_size_bytes"),
            DEFAULT_MIN_INSPECTION_SIZE_BYTES,
        )
        resolved["max_workers_override"] = self._coerce_non_negative_int(performance.get("max_workers_override"), 0)
        resolved["initial_concurrency_limit"] = self._resolve_positive_override(
            scheduler_overrides,
            "initial_concurrency_limit",
            resolved["initial_concurrency_limit"],
        )
        resolved["scheduler_poll_interval_ms"] = self._resolve_positive_override(
            scheduler_overrides,
            "poll_interval_ms",
            resolved["scheduler_poll_interval_ms"],
        )
        resolved["scheduler_scale_up_threshold_mb_s"] = self._resolve_positive_override(
            scheduler_overrides,
            "scale_up_threshold_mb_s",
            resolved["scheduler_scale_up_threshold_mb_s"],
        )
        resolved["scheduler_scale_up_backlog_threshold_mb_s"] = self._resolve_positive_override(
            scheduler_overrides,
            "scale_up_backlog_threshold_mb_s",
            resolved["scheduler_scale_up_backlog_threshold_mb_s"],
        )
        resolved["scheduler_scale_down_threshold_mb_s"] = self._resolve_positive_override(
            scheduler_overrides,
            "scale_down_threshold_mb_s",
            resolved["scheduler_scale_down_threshold_mb_s"],
        )
        resolved["scheduler_scale_up_streak_required"] = self._resolve_positive_override(
            scheduler_overrides,
            "scale_up_streak_required",
            resolved["scheduler_scale_up_streak_required"],
        )
        resolved["scheduler_scale_down_streak_required"] = self._resolve_positive_override(
            scheduler_overrides,
            "scale_down_streak_required",
            resolved["scheduler_scale_down_streak_required"],
        )
        resolved["scheduler_medium_backlog_threshold"] = self._resolve_positive_override(
            scheduler_overrides,
            "medium_backlog_threshold",
            resolved["scheduler_medium_backlog_threshold"],
        )
        resolved["scheduler_high_backlog_threshold"] = self._resolve_positive_override(
            scheduler_overrides,
            "high_backlog_threshold",
            resolved["scheduler_high_backlog_threshold"],
        )
        resolved["scheduler_medium_floor_workers"] = self._resolve_positive_override(
            scheduler_overrides,
            "medium_floor_workers",
            resolved["scheduler_medium_floor_workers"],
        )
        resolved["scheduler_high_floor_workers"] = self._resolve_positive_override(
            scheduler_overrides,
            "high_floor_workers",
            resolved["scheduler_high_floor_workers"],
        )

        return AppConfig(
            min_inspection_size_bytes=resolved["min_inspection_size_bytes"],
            scheduler_profile=resolved["scheduler_profile"],
            max_workers_override=resolved["max_workers_override"],
            initial_concurrency_limit=resolved["initial_concurrency_limit"],
            scheduler_poll_interval_ms=resolved["scheduler_poll_interval_ms"],
            scheduler_scale_up_threshold_mb_s=resolved["scheduler_scale_up_threshold_mb_s"],
            scheduler_scale_up_backlog_threshold_mb_s=resolved["scheduler_scale_up_backlog_threshold_mb_s"],
            scheduler_scale_down_threshold_mb_s=resolved["scheduler_scale_down_threshold_mb_s"],
            scheduler_scale_up_streak_required=resolved["scheduler_scale_up_streak_required"],
            scheduler_scale_down_streak_required=resolved["scheduler_scale_down_streak_required"],
            scheduler_medium_backlog_threshold=resolved["scheduler_medium_backlog_threshold"],
            scheduler_high_backlog_threshold=resolved["scheduler_high_backlog_threshold"],
            scheduler_medium_floor_workers=resolved["scheduler_medium_floor_workers"],
            scheduler_high_floor_workers=resolved["scheduler_high_floor_workers"],
            detection=self._build_detection_config(extraction_rules, performance),
            post_extract=PostExtractConfig(
                archive_cleanup_mode=self._coerce_archive_cleanup_mode(post_extract.get("archive_cleanup_mode")),
                flatten_single_directory=self._coerce_bool(post_extract.get("flatten_single_directory"), True),
            ),
            recursive_extract=self._coerce_recursive_extract(raw.get("recursive_extract")),
        )
