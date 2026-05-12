from __future__ import annotations

import pytest

from sunpack.repair.pipeline.module import RepairModule, RepairModuleSpec
from sunpack.repair.pipeline.registry import RepairModuleRegistry, discover_repair_modules, get_repair_module_registry


class _DummyZipCoarseModule(RepairModule):
    @property
    def spec(self) -> RepairModuleSpec:
        return RepairModuleSpec(name="zip_rebuild", formats=("zip",))


def test_removed_zip_coarse_module_names_cannot_register():
    registry = RepairModuleRegistry()

    with pytest.raises(ValueError, match="removed"):
        registry.register(_DummyZipCoarseModule())


def test_discovered_zip_registry_contains_only_atomic_zip_modules():
    discover_repair_modules()
    names = set(get_repair_module_registry().all())

    assert not {
        "zip_fix_boundary",
        "zip_fix_pointers",
        "zip_fix_zip64",
        "zip_rebuild",
        "zip_salvage",
        "zip_resolve_conflicts",
    } & names
    assert "zip_rebuild_cd_from_local_headers" in names
    assert "zip_fix_cd_offset" in names
