from __future__ import annotations

from sunpack.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry


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


def test_discovered_seven_zip_registry_contains_only_atomic_modules():
    discover_repair_modules()
    names = set(get_repair_module_registry().all())

    assert not {
        "seven_zip_boundary_trim",
        "seven_zip_precise_boundary_repair",
        "seven_zip_crc_field_repair",
        "seven_zip_start_header_crc_fix",
        "seven_zip_next_header_field_repair",
        "seven_zip_solid_block_partial_salvage",
        "seven_zip_non_solid_partial_salvage",
    } & names
    assert "seven_zip_fix_next_header_crc" in names
    assert "seven_zip_salvage_non_solid_entries" in names
