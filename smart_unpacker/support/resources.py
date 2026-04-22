from __future__ import annotations

import json
import os
import sys

import psutil

from smart_unpacker.support.types import AppConfig


class ResourceLocator:
    SCHEDULER_PROFILES = {"auto", "conservative", "aggressive"}

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

    def _coerce_scheduler_profile(self, value, default: str) -> str:
        if not isinstance(value, str):
            return default
        normalized = value.strip().lower()
        return normalized if normalized in self.SCHEDULER_PROFILES else default

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
        presets = {
            "conservative": conservative,
            "aggressive": aggressive,
        }
        return dict(presets.get(resolved_profile, conservative))

    def _resolve_non_negative_override(self, raw: dict, key: str, current: int) -> int:
        if key not in raw:
            return current
        return self._coerce_non_negative_int(raw.get(key), current)

    def _resolve_positive_override(self, raw: dict, key: str, current: int) -> int:
        if key not in raw:
            return current
        candidate = raw.get(key)
        try:
            parsed = int(candidate)
        except (TypeError, ValueError):
            return current
        return parsed if parsed > 0 else current

    def _get_dict(self, value) -> dict:
        return value if isinstance(value, dict) else {}

    def _get_config_value(self, root: dict, key: str, *sections):
        current = root
        for section in sections:
            current = self._get_dict(current.get(section))
            if not current:
                break
        if key in current:
            return current.get(key)
        return root.get(key)

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
        default_config = AppConfig()
        file_path = self.find_existing_resource_path("smart_unpacker_config.json") or self.get_resource_path("smart_unpacker_config.json")
        default_payload = {
            "basic": {
                "min_inspection_size_bytes": default_config.min_inspection_size_bytes,
                "scheduler_profile": default_config.scheduler_profile,
            },
            "advanced": {
                "max_workers_override": default_config.max_workers_override,
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
            },
        }
        if not os.path.exists(file_path):
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(default_payload, f, ensure_ascii=False, indent=2)
                    f.write("\n")
            except Exception:
                return default_config
            return default_config

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            return default_config

        if not isinstance(raw, dict):
            return default_config

        requested_profile = self._coerce_scheduler_profile(
            self._get_config_value(raw, "scheduler_profile", "basic"),
            default_config.scheduler_profile,
        )
        scheduler_overrides = self._get_dict(self._get_config_value(raw, "scheduler", "advanced"))
        resolved = self._build_scheduler_profile_defaults(requested_profile)
        resolved["min_inspection_size_bytes"] = self._coerce_non_negative_int(
            self._get_config_value(raw, "min_inspection_size_bytes", "basic"),
            default_config.min_inspection_size_bytes,
        )
        resolved["max_workers_override"] = self._coerce_non_negative_int(
            self._get_config_value(raw, "max_workers_override", "advanced"),
            default_config.max_workers_override,
        )
        resolved["initial_concurrency_limit"] = self._resolve_positive_override(
            scheduler_overrides,
            "initial_concurrency_limit",
            resolved["initial_concurrency_limit"],
        )
        resolved["initial_concurrency_limit"] = self._coerce_positive_int(
            self._get_config_value(raw, "initial_concurrency_limit"),
            resolved["initial_concurrency_limit"],
        )
        resolved["scheduler_poll_interval_ms"] = self._resolve_positive_override(
            scheduler_overrides,
            "poll_interval_ms",
            resolved["scheduler_poll_interval_ms"],
        )
        resolved["scheduler_poll_interval_ms"] = self._coerce_positive_int(
            self._get_config_value(raw, "scheduler_poll_interval_ms"),
            resolved["scheduler_poll_interval_ms"],
        )
        resolved["scheduler_scale_up_threshold_mb_s"] = self._resolve_positive_override(
            scheduler_overrides,
            "scale_up_threshold_mb_s",
            resolved["scheduler_scale_up_threshold_mb_s"],
        )
        resolved["scheduler_scale_up_threshold_mb_s"] = self._coerce_positive_int(
            self._get_config_value(raw, "scheduler_scale_up_threshold_mb_s"),
            resolved["scheduler_scale_up_threshold_mb_s"],
        )
        resolved["scheduler_scale_up_backlog_threshold_mb_s"] = self._resolve_positive_override(
            scheduler_overrides,
            "scale_up_backlog_threshold_mb_s",
            resolved["scheduler_scale_up_backlog_threshold_mb_s"],
        )
        resolved["scheduler_scale_up_backlog_threshold_mb_s"] = self._coerce_positive_int(
            self._get_config_value(raw, "scheduler_scale_up_backlog_threshold_mb_s"),
            resolved["scheduler_scale_up_backlog_threshold_mb_s"],
        )
        resolved["scheduler_scale_down_threshold_mb_s"] = self._resolve_positive_override(
            scheduler_overrides,
            "scale_down_threshold_mb_s",
            resolved["scheduler_scale_down_threshold_mb_s"],
        )
        resolved["scheduler_scale_down_threshold_mb_s"] = self._coerce_positive_int(
            self._get_config_value(raw, "scheduler_scale_down_threshold_mb_s"),
            resolved["scheduler_scale_down_threshold_mb_s"],
        )
        resolved["scheduler_scale_up_streak_required"] = self._resolve_positive_override(
            scheduler_overrides,
            "scale_up_streak_required",
            resolved["scheduler_scale_up_streak_required"],
        )
        resolved["scheduler_scale_up_streak_required"] = self._coerce_positive_int(
            self._get_config_value(raw, "scheduler_scale_up_streak_required"),
            resolved["scheduler_scale_up_streak_required"],
        )
        resolved["scheduler_scale_down_streak_required"] = self._resolve_positive_override(
            scheduler_overrides,
            "scale_down_streak_required",
            resolved["scheduler_scale_down_streak_required"],
        )
        resolved["scheduler_scale_down_streak_required"] = self._coerce_positive_int(
            self._get_config_value(raw, "scheduler_scale_down_streak_required"),
            resolved["scheduler_scale_down_streak_required"],
        )
        resolved["scheduler_medium_backlog_threshold"] = self._resolve_positive_override(
            scheduler_overrides,
            "medium_backlog_threshold",
            resolved["scheduler_medium_backlog_threshold"],
        )
        resolved["scheduler_medium_backlog_threshold"] = self._coerce_positive_int(
            self._get_config_value(raw, "scheduler_medium_backlog_threshold"),
            resolved["scheduler_medium_backlog_threshold"],
        )
        resolved["scheduler_high_backlog_threshold"] = self._resolve_positive_override(
            scheduler_overrides,
            "high_backlog_threshold",
            resolved["scheduler_high_backlog_threshold"],
        )
        resolved["scheduler_high_backlog_threshold"] = self._coerce_positive_int(
            self._get_config_value(raw, "scheduler_high_backlog_threshold"),
            resolved["scheduler_high_backlog_threshold"],
        )
        resolved["scheduler_medium_floor_workers"] = self._resolve_positive_override(
            scheduler_overrides,
            "medium_floor_workers",
            resolved["scheduler_medium_floor_workers"],
        )
        resolved["scheduler_medium_floor_workers"] = self._coerce_positive_int(
            self._get_config_value(raw, "scheduler_medium_floor_workers"),
            resolved["scheduler_medium_floor_workers"],
        )
        resolved["scheduler_high_floor_workers"] = self._resolve_positive_override(
            scheduler_overrides,
            "high_floor_workers",
            resolved["scheduler_high_floor_workers"],
        )
        resolved["scheduler_high_floor_workers"] = self._coerce_positive_int(
            self._get_config_value(raw, "scheduler_high_floor_workers"),
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
        )
