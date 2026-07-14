import os
import logging
from copy import deepcopy
from typing import Any, Iterable

from sunpack.filesystem.filters.modules.scene_semantics import (
    detect_scene_context_for_directory,
    is_strong_scene_context,
)
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.support.output_inventory import OutputInventory


LOGGER = logging.getLogger(__name__)


class NestedOutputScanPolicy:
    """Locate extracted output directories that require full archive detection."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self._output_scan_config = self._build_recursive_output_scan_config()

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
        for path, _size in candidates:
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

    def _build_recursive_output_scan_config(self) -> dict[str, Any]:
        config = deepcopy(self.config)
        filesystem = config.get("filesystem")
        if not isinstance(filesystem, dict):
            filesystem = {}
            config["filesystem"] = filesystem
        filesystem["directory_scan_mode"] = "recursive"
        return config
