import os
import logging
from copy import deepcopy
from functools import lru_cache
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


LOGGER = logging.getLogger(__name__)


class NestedOutputScanPolicy:
    """Detection-owned policy for deciding whether extracted outputs may contain archives."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        embedded_config = module_config(config, "processors", "embedded_archive")
        if not embedded_config:
            embedded_config = self._rule_config("scoring", "embedded_payload_identity")
        extension_config = self._rule_config("scoring", "extension")
        self._standard_exts, self._carrier_exts, self._ambiguous_exts = _compile_extension_rules(
            _freeze_extension_score_groups(extension_config.get("extension_score_groups", [])),
            _freeze_strings(embedded_config.get("carrier_exts")),
            _freeze_strings(embedded_config.get("ambiguous_resource_exts")),
        )
        self._output_scan_config = self._build_recursive_output_scan_config()

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
        inventory_files = self._inventory_files(inventory)
        snapshot = None
        if inventory_files is None:
            snapshot = DirectoryScanner(target_dir, config=self._output_scan_config).scan()
        ctx = detect_scene_context_for_directory(target_dir, entries=snapshot.entries if snapshot is not None else None)
        if is_strong_scene_context(ctx):
            LOGGER.info(
                "skipping strong scene output directory: %s @ %s",
                ctx.get("scene_type"),
                os.path.basename(target_dir) or target_dir,
            )
            return []

        roots = []
        seen = set()
        candidates = (
            ((str(entry.path), entry.size) for entry in snapshot.entries if not entry.is_dir)
            if snapshot is not None
            else inventory_files
        )
        for path, size in candidates:
            if self._should_consider_candidate(path, size=size):
                parent = os.path.abspath(os.path.dirname(path))
                key = os.path.normcase(parent)
                if key not in seen:
                    seen.add(key)
                    roots.append(parent)
        return roots

    @staticmethod
    def _inventory_files(inventory: OutputInventory | None) -> Iterable[tuple[str, int]] | None:
        if inventory is None or not inventory.stats.exists or not inventory.stats.is_dir:
            return None
        root = os.path.abspath(inventory.root)
        return (
            (os.path.join(root, str(item.get("path") or "")), int(item.get("size", 0) or 0))
            for item in inventory.files
            if item.get("path")
        )

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

    def _build_recursive_output_scan_config(self) -> dict[str, Any]:
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
        if ext in self._standard_exts:
            return True
        if ext in self._carrier_exts:
            return self._size_at_least(path, size, 1024 * 1024)
        if ext in self._ambiguous_exts and any(token in filename for token in ("archive", "zip", "rar", "7z", "part")):
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


def _freeze_strings(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple, set)):
        return ()
    return tuple(str(value) for value in values if isinstance(value, str) and value.strip())


def _freeze_extension_score_groups(values: Any) -> tuple[tuple[int, tuple[str, ...]], ...]:
    if not isinstance(values, list):
        return ()
    groups: list[tuple[int, tuple[str, ...]]] = []
    for group in values:
        if not isinstance(group, dict):
            continue
        try:
            score = int(group.get("score"))
        except (TypeError, ValueError):
            continue
        groups.append((score, _freeze_strings(group.get("extensions"))))
    return tuple(groups)


@lru_cache(maxsize=64)
def _compile_extension_rules(
    score_groups: tuple[tuple[int, tuple[str, ...]], ...],
    carrier_exts: tuple[str, ...],
    ambiguous_exts: tuple[str, ...],
) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    groups = [{"score": score, "extensions": list(extensions)} for score, extensions in score_groups]
    standard = set(normalize_extension_score_groups(groups))
    standard.add(".exe")
    return (
        frozenset(standard),
        frozenset(normalize_exts(carrier_exts)),
        frozenset(normalize_exts(ambiguous_exts)),
    )
