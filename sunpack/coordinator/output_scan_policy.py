import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

from sunpack.config.detection_view import module_config, rule_pipeline_config
from sunpack.contracts.filesystem import DirectorySnapshot, FileEntry
from sunpack.filesystem.filters.modules.scene_semantics import (
    detect_scene_context_for_directory,
    is_strong_scene_context,
)
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.support.extensions import normalize_extension_score_groups, normalize_exts
from sunpack.support.output_inventory import OutputInventory


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
        return bool(self._candidate_parent_roots(target_dir))

    def _candidate_parent_roots(
        self,
        target_dir: str,
        inventory: OutputInventory | None = None,
    ) -> list[str]:
        # Output discovery is inherently recursive and must not inherit the
        # user's initial directory-scan depth. Embedded segment extraction adds
        # a child directory (for example embedded_00_rar), while the next round
        # may intentionally remain current-directory-only.
        snapshot = self._snapshot_from_inventory(target_dir, inventory)
        if snapshot is None:
            snapshot = DirectoryScanner(target_dir, config=self._recursive_output_scan_config()).scan()
        ctx = detect_scene_context_for_directory(target_dir, entries=snapshot.entries)
        if is_strong_scene_context(ctx):
            print(
                "[SCAN] Skipping strong scene output directory: "
                f"{ctx.get('scene_type')} @ {os.path.basename(target_dir) or target_dir}"
            )
            return []

        roots = []
        seen = set()
        for entry in snapshot.entries:
            if self.should_consider_entry_for_nested_scan(entry):
                parent = os.path.abspath(os.path.dirname(str(entry.path)))
                key = os.path.normcase(parent)
                if key not in seen:
                    seen.add(key)
                    roots.append(parent)
        return roots

    def scan_roots_from_outputs(
        self,
        output_dirs: Iterable[str],
        inventories: dict[str, dict[str, Any]] | None = None,
    ) -> list[str]:
        roots = []
        seen = set()
        inventories = inventories or {}
        for output_dir in output_dirs:
            if not output_dir or not os.path.isdir(output_dir):
                continue
            inventory = OutputInventory.from_dict(
                inventories.get(os.path.normcase(os.path.abspath(output_dir))),
                expected_root=output_dir,
            )
            for root in self._candidate_parent_roots(output_dir, inventory):
                key = os.path.normcase(os.path.abspath(root))
                if key in seen:
                    continue
                seen.add(key)
                roots.append(root)
        return roots

    @staticmethod
    def _snapshot_from_inventory(
        target_dir: str,
        inventory: OutputInventory | None,
    ) -> DirectorySnapshot | None:
        if inventory is None or not inventory.stats.exists or not inventory.stats.is_dir:
            return None
        root = os.path.abspath(target_dir)
        entries = [
            FileEntry(
                path=Path(root) / str(item.get("path") or ""),
                is_dir=False,
                size=int(item.get("size", 0) or 0),
            )
            for item in inventory.files
            if item.get("path")
        ]
        return DirectorySnapshot(root_path=Path(root), entries=entries)

    def _recursive_output_scan_config(self) -> dict[str, Any]:
        config = deepcopy(self.config)
        filesystem = config.get("filesystem")
        if not isinstance(filesystem, dict):
            filesystem = {}
            config["filesystem"] = filesystem
        filesystem["directory_scan_mode"] = "recursive"
        return config

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
