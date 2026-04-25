import os
from typing import Any, Dict, Iterable

from smart_unpacker.config.detection_view import module_config, rule_pipeline_config
from smart_unpacker.contracts.filesystem import FileEntry
from smart_unpacker.detection.scene.directory_context import (
    detect_scene_context_for_directory,
    is_strong_scene_context,
)
from smart_unpacker.filesystem.directory_scanner import DirectoryScanner


class OutputScanPolicy:
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def should_consider_file_for_nested_scan(self, path: str) -> bool:
        return self._should_consider_candidate(path, size=None)

    def should_consider_entry_for_nested_scan(self, entry: FileEntry) -> bool:
        if entry.is_dir:
            return False
        return self._should_consider_candidate(str(entry.path), size=entry.size)

    def _should_consider_candidate(self, path: str, size: int | None) -> bool:
        filename = os.path.basename(path).lower()
        _, ext = os.path.splitext(filename)
        embedded_config = module_config(self.config, "processors", "embedded_archive")
        if not embedded_config:
            embedded_config = self._rule_config("scoring", "archive_identity")

        extension_config = self._rule_config("scoring", "extension")
        standard_exts = set(self._normalize_extension_score_groups(extension_config.get("extension_score_groups", [])))
        standard_exts.add(".exe")

        carrier_exts = self._configured_extension_set(embedded_config.get("carrier_exts"), [])
        ambiguous_exts = self._configured_extension_set(
            embedded_config.get("ambiguous_resource_exts"),
            [],
        )

        if ext in standard_exts:
            return True
        if ext in carrier_exts:
            return self._size_at_least(path, size, 1024 * 1024)
        if ext in ambiguous_exts and any(token in filename for token in ("archive", "zip", "rar", "7z", "part")):
            return True
        if ".part" in filename or filename.endswith(".001"):
            return True
        if not ext:
            return self._size_at_least(path, size, 2 * 1024 * 1024)
        return False

    def should_scan_output_dir(self, target_dir: str) -> bool:
        ctx = detect_scene_context_for_directory(target_dir)
        if is_strong_scene_context(ctx):
            print(
                "[SCAN] Skipping strong scene output directory: "
                f"{ctx.get('scene_type')} @ {os.path.basename(target_dir) or target_dir}"
            )
            return False

        snapshot = DirectoryScanner(target_dir, config=self.config).scan()
        for entry in snapshot.entries:
            if self.should_consider_entry_for_nested_scan(entry):
                return True
        return False

    def scan_roots_from_outputs(self, output_dirs: Iterable[str]) -> list[str]:
        return [
            output_dir
            for output_dir in output_dirs
            if output_dir and os.path.isdir(output_dir) and self.should_scan_output_dir(output_dir)
        ]

    def _rule_config(self, layer: str, name: str) -> Dict[str, Any]:
        for rule in rule_pipeline_config(self.config).get(layer, []):
            if isinstance(rule, dict) and rule.get("name") == name:
                return rule
        return {}

    def _normalize_extension_score_groups(self, values) -> dict[str, int]:
        if not isinstance(values, list):
            return {}
        normalized = {}
        for group in values:
            if not isinstance(group, dict):
                continue
            try:
                score = int(group.get("score"))
            except (TypeError, ValueError):
                continue
            for ext in group.get("extensions") or []:
                if not isinstance(ext, str) or not ext.strip():
                    continue
                normalized_ext = ext.strip().lower()
                normalized[normalized_ext if normalized_ext.startswith(".") else f".{normalized_ext}"] = score
        return normalized

    def _configured_extension_set(self, values, fallback) -> set[str]:
        normalized = set()
        source = values if isinstance(values, list) else fallback
        for value in source:
            if not isinstance(value, str) or not value.strip():
                continue
            ext = value.strip().lower()
            normalized.add(ext if ext.startswith(".") else f".{ext}")
        return normalized

    def _size_at_least(self, path: str, size: int | None, minimum_bytes: int) -> bool:
        if size is not None:
            return size >= minimum_bytes
        try:
            return os.path.getsize(path) >= minimum_bytes
        except OSError:
            return False
