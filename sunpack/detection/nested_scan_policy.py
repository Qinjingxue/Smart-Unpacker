import os
from typing import Any, Iterable

from sunpack.config.detection_view import module_config, rule_pipeline_config
from sunpack.contracts.filesystem import FileEntry
from sunpack.filesystem.filters.modules.scene_semantics import (
    detect_scene_context_for_directory,
    is_strong_scene_context,
)
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.support.extensions import normalize_extension_score_groups, normalize_exts


class NestedOutputScanPolicy:
    """Detection-owned policy for deciding whether extracted outputs may contain archives."""

    def __init__(self, config: dict[str, Any]):
        self.config = config

    def should_consider_file_for_nested_scan(self, path: str) -> bool:
        return self._should_consider_candidate(path, size=None)

    def should_consider_entry_for_nested_scan(self, entry: FileEntry) -> bool:
        if entry.is_dir:
            return False
        return self._should_consider_candidate(str(entry.path), size=entry.size)

    def should_scan_output_dir(self, target_dir: str) -> bool:
        snapshot = DirectoryScanner(target_dir, config=self.config).scan()
        ctx = detect_scene_context_for_directory(target_dir, entries=snapshot.entries)
        if is_strong_scene_context(ctx):
            print(
                "[SCAN] Skipping strong scene output directory: "
                f"{ctx.get('scene_type')} @ {os.path.basename(target_dir) or target_dir}"
            )
            return False

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

    def _should_consider_candidate(self, path: str, size: int | None) -> bool:
        filename = os.path.basename(path).lower()
        _, ext = os.path.splitext(filename)
        embedded_config = module_config(self.config, "processors", "embedded_archive")
        if not embedded_config:
            embedded_config = self._rule_config("scoring", "embedded_payload_identity")

        extension_config = self._rule_config("scoring", "extension")
        standard_exts = set(normalize_extension_score_groups(extension_config.get("extension_score_groups", [])))
        standard_exts.add(".exe")

        carrier_exts = normalize_exts(embedded_config.get("carrier_exts"))
        ambiguous_exts = normalize_exts(embedded_config.get("ambiguous_resource_exts"))

        if ext in standard_exts:
            return True
        if ext in carrier_exts:
            return self._size_at_least(path, size, 1024 * 1024)
        if ext in ambiguous_exts and any(token in filename for token in ("archive", "zip", "rar", "7z", "part")):
            return True
        if filename == "#0" and self._parent_suggests_tar_stream(path):
            return True
        if ".part" in filename or filename.endswith(".001"):
            return True
        if not ext:
            return self._size_at_least(path, size, 2 * 1024 * 1024)
        return False

    def _rule_config(self, layer: str, name: str) -> dict[str, Any]:
        for rule in rule_pipeline_config(self.config).get(layer, []):
            if isinstance(rule, dict) and rule.get("name") == name:
                return rule
        return {}

    def _size_at_least(self, path: str, size: int | None, minimum_bytes: int) -> bool:
        if size is not None:
            return size >= minimum_bytes
        try:
            return os.path.getsize(path) >= minimum_bytes
        except OSError:
            return False

    def _parent_suggests_tar_stream(self, path: str) -> bool:
        parent_name = os.path.basename(os.path.dirname(path)).lower()
        if parent_name.endswith("_extracted"):
            parent_name = parent_name[: -len("_extracted")]
        return parent_name.endswith((
            ".tar",
            ".tar.gz",
            ".tgz",
            ".tar.bz2",
            ".tbz",
            ".tbz2",
            ".tar.xz",
            ".txz",
            ".tar.zst",
            ".tzst",
            "_tar",
            "_tar.gz",
            "_tgz",
            "_tar.bz2",
            "_tbz",
            "_tbz2",
            "_tar.xz",
            "_txz",
            "_tar.zst",
            "_tzst",
        ))
