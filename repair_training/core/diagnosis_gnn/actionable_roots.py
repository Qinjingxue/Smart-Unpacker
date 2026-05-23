from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from repair_training.core.diagnosis_gnn.root_cases import ROOT_CASES, ROOT_CASE_SET, canonical_root_case


ACTIONABLE_ROOT_SEMANTICS = "repair_actionable_root_v2"
ACTIONABLE_LABEL_SOURCE = "oracle_best_path_first_action"
ROOT_HYPOTHESIS_TRAINING_OBJECTIVE = "root_hypothesis_probe_world_v1"


MODULE_TO_ACTIONABLE_ROOTS: dict[str, tuple[str, ...]] = {
    "archive_carrier_crop_deep_recovery": ("sfx_prefix.bytes",),
    "zip_fix_eocd_record": ("eocd.cd_offset", "eocd.cd_size", "eocd.entry_count", "eocd.comment_length"),
    "zip_fix_eocd_comment_length": ("eocd.comment_length",),
    "zip_fix_cd_offset": ("eocd.cd_offset",),
    "zip_fix_cd_entry_count": ("eocd.entry_count",),
    "zip_rebuild_cd_from_local_headers": ("eocd.cd_size", "central_directory.local_header_offset"),
    "zip_rebuild_cd_preserve_raw_names": ("entry_name", "eocd.cd_size", "central_directory.local_header_offset"),
    "zip_rebuild_cd_from_data_descriptors": ("data_descriptor.record", "data_descriptor.size", "central_directory.compressed_size"),
    "zip_fix_local_header_fields": (
        "local_header.signature",
        "compression_method",
        "local_header.flags",
        "local_header.crc",
        "local_header.compressed_size",
    ),
    "zip_local_header_partial_scan": ("local_header.signature", "payload.compressed_data"),
    "zip_fix_extra_field_length": ("generic_extra_field",),
    "zip_fix_zip64_locator": ("zip64.locator",),
    "zip_fix_zip64_eocd": ("zip64.eocd",),
    "zip_fix_zip64_extra_size": ("zip64.extra_length", "zip64.uncompressed_size"),
    "zip_trim_trailing_junk": ("tail.trailing_bytes",),
    "zip_normalize_data_descriptor_flags": ("central_directory.flags", "local_header.flags", "data_descriptor.record"),
    "zip_reconcile_cd_entry_names_from_local_headers": ("entry_name",),
    "zip_reconcile_cd_local_headers": (
        "central_directory.local_header_offset",
        "central_directory.flags",
        "central_directory.crc",
        "central_directory.compressed_size",
        "compression_method",
        "entry_name",
    ),
    "zip_reconcile_cd_data_descriptor_conflict": (
        "data_descriptor.record",
        "data_descriptor.crc",
        "data_descriptor.size",
        "central_directory.compressed_size",
        "central_directory.crc",
    ),
    "zip_remove_spurious_data_descriptor": ("data_descriptor.record",),
    "zip_quarantine_failed_entries": ("payload.compressed_data", "central_directory.crc", "local_header.crc"),
    "zip_salvage_verified_entries": ("payload.compressed_data", "central_directory.crc", "local_header.crc"),
    "zip_partial_salvage_missing_volume": ("split_volume.missing_range",),
    "zip_resolve_duplicate_entries": ("central_directory.crc", "entry_name"),
    "zip_resolve_overlapping_entries": ("central_directory.compressed_size", "payload.compressed_data"),
    "archive_nested_payload_salvage": ("payload.compressed_data",),
    "zip_boundary": ("sfx_prefix.bytes", "tail.trailing_bytes"),
    "zip_directory": ("eocd.cd_offset", "eocd.cd_size", "central_directory.local_header_offset"),
}


def roots_for_module(module_name: str) -> tuple[str, ...]:
    return MODULE_TO_ACTIONABLE_ROOTS.get(str(module_name or ""), ())


def modules_for_root(root_case: str) -> tuple[str, ...]:
    root = canonical_root_case(root_case) or str(root_case or "")
    if root not in ROOT_CASE_SET:
        return ()
    return tuple(
        module
        for module, roots in sorted(MODULE_TO_ACTIONABLE_ROOTS.items())
        if root in roots
    )


def actionable_roots_for_module(module_name: str, injected_roots: Iterable[str] | None = None) -> list[str]:
    roots = list(roots_for_module(module_name))
    if not roots:
        return []
    injected = _canonical_roots(injected_roots or [])
    narrowed = [root for root in roots if root in injected]
    return sorted(set(narrowed or roots), key=ROOT_CASES.index)


def best_module_action(actions: Iterable[Any]) -> dict[str, Any]:
    module_actions = []
    for action in actions or []:
        raw = action.to_dict() if hasattr(action, "to_dict") else dict(action or {})
        if str(raw.get("action_type") or "") != "module":
            continue
        module = str(raw.get("module_name") or raw.get("module") or "")
        if not module:
            continue
        module_actions.append(raw)
    if not module_actions:
        return {}
    return max(module_actions, key=lambda item: float(item.get("action_q_value") or item.get("q_value") or 0.0))


def actionable_roots_from_actions(actions: Iterable[Any], injected_roots: Iterable[str] | None = None) -> list[str]:
    best = best_module_action(actions)
    if not best:
        return []
    return actionable_roots_for_module(str(best.get("module_name") or best.get("module") or ""), injected_roots)


def unmapped_zip_modules(module_names: Iterable[str]) -> list[str]:
    return sorted({str(name) for name in module_names if str(name) and str(name) not in MODULE_TO_ACTIONABLE_ROOTS})


def _canonical_roots(values: Iterable[str]) -> set[str]:
    output = set()
    for value in values:
        root = canonical_root_case(str(value or ""))
        if root:
            output.add(root)
    return output
