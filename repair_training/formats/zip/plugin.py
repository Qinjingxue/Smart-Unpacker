from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import random

from repair_training.core.plugin import TrainingFeatureSpec, TrainingFormatPlugin, TrainingLabelSchema
from repair_training.formats.zip.build_material_impl import (
    _apply_profile_metadata,
    _choose_source_for_profile,
    _distributed_zip_sources,
    _profile_layer_name,
    build_corpus_corruption_case,
)
from sunpack.repair.context import zip_route_evidence_flags


FORMAT_NAME = "zip"
PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_DISTRIBUTION = PACKAGE_ROOT / "distributions" / "damage_distribution_zip_root_transition_v3.json"
ZIP_ZONE_LABELS = (
    "sfx_prefix",
    "local_header",
    "data_descriptor",
    "extra_field",
    "payload",
    "central_directory",
    "zip64",
    "eocd",
    "tail",
    "split_volume",
    "unknown",
)
ZIP_FIELD_LABELS = (
    "eocd.comment",
    "eocd.comment_length",
    "eocd.cd_offset",
    "eocd.entry_count",
    "central_directory.header",
    "central_directory.flags",
    "central_directory.filename",
    "central_directory.extra",
    "central_directory.extra_length",
    "central_directory.local_header_offset",
    "central_directory.crc",
    "central_directory.compressed_size",
    "central_directory.external_attributes",
    "local_header.header",
    "local_header.flags",
    "local_header.filename",
    "local_header.extra",
    "local_header.extra_length",
    "local_header.crc",
    "local_header.compressed_size",
    "data_descriptor.record",
    "data_descriptor.crc",
    "data_descriptor.size",
    "payload.crc_region",
    "payload.compressed_data",
    "zip64.eocd",
    "zip64.locator",
    "zip64.extra",
    "zip64.extra_length",
    "zip64.uncompressed_size",
    "tail.comment",
    "tail.trailing_bytes",
    "sfx_prefix.bytes",
    "split_volume.missing_range",
)
ZIP_MODULE_FAMILIES = {
    "boundary": {
        "zip_trim_trailing_junk",
        "zip_fix_eocd_comment_length",
    },
    "pointer": {
        "zip_fix_eocd_record",
        "zip_fix_cd_offset",
        "zip_fix_cd_entry_count",
        "zip_fix_local_header_fields",
    },
    "zip64": {
        "zip_fix_zip64_locator",
        "zip_fix_zip64_eocd",
        "zip_fix_zip64_extra_size",
    },
    "descriptor": {
        "zip_rebuild_cd_from_data_descriptors",
        "zip_remove_spurious_data_descriptor",
        "zip_normalize_data_descriptor_flags",
        "zip_reconcile_cd_entry_names_from_local_headers",
        "zip_reconcile_cd_data_descriptor_conflict",
    },
    "rebuild": {
        "zip_rebuild_cd_from_local_headers",
        "zip_reconcile_cd_local_headers",
    },
    "salvage": {
        "zip_quarantine_failed_entries",
        "zip_salvage_verified_entries",
        "zip_partial_salvage_missing_volume",
        "zip_local_header_partial_scan",
    },
    "conflict": {
        "zip_resolve_duplicate_entries",
        "zip_resolve_overlapping_entries",
    },
    "naming": {
        "zip_rebuild_cd_preserve_raw_names",
    },
}
ZIP_EVAL_PROFILES = (
    "zip_comment_overlap_eocd_shifted",
    "zip_data_descriptor_cd_conflict",
    "zip_data_descriptor_payload_bad",
    "zip_duplicate_entry_crc_conflict",
    "zip_extra_field_length_bad",
    "zip_mixed_method_one_entry_bad",
    "zip_non_utf8_filename_directory_rebuild",
    "zip_sfx_cd_damage",
    "zip_sfx_payload_damage",
    "zip_split_missing_middle_volume",
    "zip_split_tail_volume_truncated",
    "zip_zip64_eocd_locator_bad",
    "zip_zip64_extra_size_mismatch",
)
ZIP_EVAL_COMPOUND_PROFILES = (
    "compound_boundary_drop_cd_payload_bad",
    "compound_comment_eocd_count_cd_rebuild",
    "compound_descriptor_fake_span_flags_cd_offset",
    "compound_duplicate_descriptor_name_conflict",
    "compound_extra_field_cd_offset_payload_bad",
    "compound_non_utf8_duplicate_cd_offset",
    "compound_sfx_cd_offset_payload_partial",
    "compound_sfx_split_descriptor_payload_partial",
    "compound_split_sidecar_cd_count_local_header",
    "compound_zip64_locator_extra_trailing_junk",
)


def get_training_plugin() -> TrainingFormatPlugin:
    return TrainingFormatPlugin(
        format_name=FORMAT_NAME,
        default_run_name="zip_policy_lab",
        default_collection_budget={
            "workers": 6,
            "max_rounds": 6,
            "max_states": 20,
            "branch_top_k": 5,
            "root_branch_top_k": 5,
            "materialize_top_k": 8,
        },
        default_distribution=DEFAULT_DISTRIBUTION,
        model_output_subdir=Path("models") / "zip_policy_lab",
        collection_record_context=collection_record_context,
        resolve_collection_material_report=resolve_collection_material_report,
        load_material_index=load_material_index,
        compact_material_distribution=compact_material_distribution,
        damage_label_schema=damage_label_schema,
        damage_feature_spec=damage_feature_spec,
        action_feature_spec=action_feature_spec,
        lightgbm_params=lightgbm_params,
        postprocess_damage_prediction=postprocess_damage_prediction,
        action_label=action_label,
        damage_eval_profile_plan=damage_eval_profile_plan,
        generate_damage_eval_records=generate_damage_eval_records,
        damage_eval_metadata=damage_eval_metadata,
    )


def damage_label_schema() -> TrainingLabelSchema:
    zone_labels = tuple(f"zone:{label}" for label in ZIP_ZONE_LABELS)
    field_labels = tuple(f"field:{label}" for label in ZIP_FIELD_LABELS)
    return TrainingLabelSchema(
        labels=zone_labels + field_labels,
        metadata={
            "format": "zip",
            "taxonomy": "zip",
            "taxonomy_version": 2,
            "schema_version": 2,
            "analysis_target": "location_only",
            "label_groups": {
                "zone": list(zone_labels),
                "field": list(field_labels),
            },
        },
    )


def damage_feature_spec() -> TrainingFeatureSpec:
    return TrainingFeatureSpec(
        include_prefixes=(
            "format",
            "runtime_context.analysis_summary.",
            "runtime_context.analysis_native_probe.",
            "runtime_context.archive_authentication.",
            "runtime_context.extraction_summary.",
            "runtime_context.verification_summary.",
            "runtime_context.job_summary.",
            "runtime_context.archive_state.",
            "diagnosis.",
            "repair_history.",
        ),
        categorical_paths=(
            "format",
            "runtime_context.analysis_summary.format",
            "runtime_context.analysis_summary.prepass_status",
            "runtime_context.analysis_summary.prepass_format",
            "runtime_context.analysis_summary.fuzzy_status",
            "runtime_context.analysis_summary.fuzzy_archive_type",
            "runtime_context.extraction_summary.failure_stage",
            "runtime_context.extraction_summary.failure_kind",
            "runtime_context.extraction_summary.native_status",
            "runtime_context.verification_summary.decision_hint",
            "runtime_context.verification_summary.assessment_status",
            "runtime_context.verification_summary.source_integrity",
            "runtime_context.job_summary.source_kind",
            "runtime_context.job_summary.source_format_hint",
        ),
        ignore_prefixes=(
            "runtime_context.archive_state.state",
            "runtime_context.archive_state.patch_digest",
            "job.source_input.path",
            "runtime_context.knowledge_projection.source_fingerprint",
        ),
        ignore_paths=("source_identity.clean_sha256", "source_identity.corrupted_sha256"),
    )


def action_feature_spec() -> TrainingFeatureSpec:
    return TrainingFeatureSpec(
        include_prefixes=("action_type", "candidate_snapshot.", "damage_analysis_target.", "current_recovery.", "next_recovery.", "recovery_delta"),
        categorical_paths=(
            "action_type",
            "candidate_snapshot.action_type",
            "candidate_snapshot.module_name",
            "candidate_snapshot.module_family",
            "candidate_snapshot.last_patch_module",
            "candidate_snapshot.recovery_status",
            "candidate_snapshot.status",
            "current_recovery.status",
            "current_recovery.decision_hint",
            "next_recovery.status",
            "next_recovery.decision_hint",
        ),
        ignore_prefixes=(
            "candidate_snapshot.patch_digest",
            "candidate_snapshot.recovery_snapshot.state_digest",
            "candidate_snapshot.recovery_snapshot.extraction.archive",
            "candidate_snapshot.recovery_snapshot.extraction.out_dir",
            "candidate_snapshot.recovery_snapshot.verification.files",
            "candidate_snapshot.workspace_paths",
            "candidate_snapshot.repaired_input.path",
        ),
    )


def lightgbm_params(model_type: str) -> dict[str, Any]:
    if model_type == "repair_action":
        return {
            "objective": "lambdarank",
            "n_estimators": 80,
            "learning_rate": 0.04,
            "num_leaves": 15,
            "min_child_samples": 2,
            "subsample": 0.9,
            "colsample_bytree": 0.9,
        }
    return {
        "n_estimators": 70,
        "learning_rate": 0.04,
        "num_leaves": 15,
        "min_child_samples": 2,
        "is_unbalance": True,
        "subsample": 0.9,
        "colsample_bytree": 0.9,
    }


def action_label(row: dict[str, Any]) -> int:
    action = str(row.get("action_type") or "")
    value = _float(row.get("long_term_value"))
    current = _float((row.get("current_recovery") or {}).get("score") if isinstance(row.get("current_recovery"), dict) else 0.0)
    next_score = _float((row.get("next_recovery") or {}).get("score") if isinstance(row.get("next_recovery"), dict) else 0.0)
    regret = _float(row.get("regret"))
    label = int(round((value + 1.0) * 10.0))
    if row.get("is_best_action"):
        label = max(label, 24)
    if regret > 0:
        label -= int(min(12, round(regret * 8.0)))
    if action == "give_up" and current > 0.0:
        label = min(label, 3)
    if action == "stop" and current >= 0.95:
        label = max(label, 28)
    if action == "undo_patch" and next_score > current:
        label = max(label, 22 + int(min(6, round((next_score - current) * 6.0))))
    return int(max(0, min(31, label)))


def damage_eval_profile_plan(samples: int, seed: int) -> list[str]:
    rng = random.Random(int(seed or 0))
    samples = max(0, int(samples or 0))
    compound_count = int(round(samples * 0.45))
    single_count = max(0, samples - compound_count)
    plan = [
        ZIP_EVAL_PROFILES[index % len(ZIP_EVAL_PROFILES)]
        for index in range(single_count)
    ] + [
        ZIP_EVAL_COMPOUND_PROFILES[index % len(ZIP_EVAL_COMPOUND_PROFILES)]
        for index in range(compound_count)
    ]
    rng.shuffle(plan)
    return plan[:samples]


def generate_damage_eval_records(
    material_root: str | Path,
    workspace: str | Path,
    seed: int,
    samples: int,
    profile_plan: list[str],
) -> list[dict[str, Any]]:
    material_root = Path(material_root)
    workspace = Path(workspace)
    rng = random.Random(int(seed or 0))
    sources = _distributed_zip_sources(material_root / "zip", set())
    if not sources:
        return []
    profile_plan = list(profile_plan or damage_eval_profile_plan(samples, seed))
    records: list[dict[str, Any]] = []
    source_counts: dict[str, int] = {}
    variant_counts: dict[str, int] = {}
    for index, profile in enumerate(profile_plan[: max(0, int(samples or 0))]):
        source_item = _choose_source_for_profile(sources, profile, CounterProxy(source_counts), rng)
        source = Path(source_item["source"])
        source_key = str(source)
        variant_index = int(variant_counts.get(source_key, 0))
        variant_counts[source_key] = variant_index + 1
        source_counts[source_key] = int(source_counts.get(source_key, 0)) + 1
        source_derivation = dict(source_item.get("source_derivation") or {})
        zip_password = str(source_derivation.get("zip_password") or "")
        case_root = workspace / str(source_item.get("source_archive_id") or source.stem) / f"eval_{index:05d}"
        case = build_corpus_corruption_case(
            case_root,
            source_path=source,
            fmt="zip",
            seed=rng.randrange(1, 2**31 - 1) + index,
            variant_index=variant_index,
            damage_profile=profile,
            source_derivation=source_derivation,
            password=zip_password or None,
        )
        record = case.corpus_manifest_record(
            source_archive_id=str(source_item.get("source_archive_id") or source.stem),
            source_path=str(source),
            damage_profile=profile,
            variant_index=variant_index,
            material_format="zip",
            material_sample_id=str(Path(source_item.get("sample_dir") or "").name),
        )
        if zip_password and not record.get("password"):
            record["password"] = zip_password
        record["source_derivation"] = source_derivation
        record["damage_layer"] = _profile_layer_name(profile)
        record["requested_damage_layer"] = record["damage_layer"]
        record["actual_damage_layer"] = record["damage_layer"]
        record["damage_layer_weight"] = 1.0
        _apply_profile_metadata(record, profile, {"profile_layer": record["damage_layer"]})
        record.setdefault("metadata", {})["eval_seed"] = int(seed or 0)
        record["eval_profile"] = profile
        records.append(record)
    return records


def damage_eval_metadata() -> dict[str, Any]:
    return {
        "format": "zip",
        "single_profiles": list(ZIP_EVAL_PROFILES),
        "compound_profiles": list(ZIP_EVAL_COMPOUND_PROFILES),
        "compound_target_ratio": 0.45,
    }


class CounterProxy:
    def __init__(self, values: dict[str, int]):
        self.values = values

    def __getitem__(self, key: str) -> int:
        return int(self.values.get(str(key), 0))


def zip_module_family(module_name: str) -> str:
    module = str(module_name or "")
    if module == "undo_patch":
        return "control_undo"
    if module == "stop":
        return "control_stop"
    if module == "give_up":
        return "control_give_up"
    for family, modules in ZIP_MODULE_FAMILIES.items():
        if module in modules:
            return family
    return "zip_other"


def postprocess_damage_prediction(raw_scores: dict[str, Any]) -> dict[str, Any]:
    scores = _score_map(raw_scores)
    threshold = _float(raw_scores.get("threshold") if isinstance(raw_scores, dict) else None, default=0.5)
    selected = {label: score for label, score in scores.items() if score >= threshold}
    location_scores = {label: score for label, score in scores.items() if label.startswith(("zone:", "field:"))}
    if not selected and location_scores:
        label, score = max(location_scores.items(), key=lambda item: item[1])
        selected[label] = score
    damage_labels = sorted(selected)
    zone_labels = [label.split(":", 1)[1] for label in damage_labels if label.startswith("zone:")]
    for field in [label.split(":", 1)[1] for label in damage_labels if label.startswith("field:")]:
        zone = _zone_from_field(field)
        if zone:
            zone_labels.append(zone)
    return {
        "format": "zip",
        "damage_labels": damage_labels,
        "damage_zones": [{"kind": zone, "path": zone} for zone in sorted(set(zone_labels))],
        "confidence": max(selected.values(), default=0.0),
        "route_hints": [],
        "blocking_reasons": [],
        "metadata": {
            "threshold": threshold,
            "selected_scores": selected,
            "taxonomy": "zip",
            "analysis_target": "location_only",
        },
    }


def collection_record_context(record: dict[str, Any]) -> dict[str, Any]:
    structure = dict(record.get("zip_structure_features") or {})
    tags = [str(item) for item in record.get("zip_container_tags") or [] if str(item)]
    profile = str(record.get("damage_profile") or record.get("profile") or "")
    source_derivation = dict(record.get("source_derivation") or {})
    route_flags = zip_route_evidence_flags({
        "format": "zip",
        "source_input": record.get("damaged_input") or {},
        "zip_structure_features": structure,
        "zip_container_tags": tags,
        "damage_profile": profile,
        "source_derivation": source_derivation,
        "damage_flags": list(record.get("runtime_damage_flags") or record.get("damage_flags") or []),
    })
    return {
        "payloads": {
            "format.zip": {"structure": structure, "container_tags": tags, "route_evidence_flags": route_flags},
            "source": {"profile": profile, "derivation": source_derivation},
            "training": {"sample_id": str(record.get("sample_id") or ""), "damage_profile": profile},
        },
        "flags": {"format.zip.route_evidence": route_flags},
    }


def _score_map(raw_scores: dict[str, Any]) -> dict[str, float]:
    if not isinstance(raw_scores, dict):
        return {}
    raw = raw_scores.get("scores") if isinstance(raw_scores.get("scores"), dict) else raw_scores
    schema = damage_label_schema()
    output: dict[str, float] = {}
    for label in schema.labels:
        if raw.get(label) is not None:
            output[label] = _float(raw.get(label))
    return output


def _zone_from_field(field: str) -> str:
    text = str(field or "")
    if "." not in text:
        return text
    head = text.split(".", 1)[0]
    if head == "sfx_prefix":
        return "sfx_prefix"
    if head == "split_volume":
        return "split_volume"
    if head == "zip64":
        return "zip64"
    return head


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        if value and value not in output:
            output.append(value)
    return output


def _float(value: Any, *, default: float = 0.0) -> float:
    try:
        return float(value if value is not None else default)
    except (TypeError, ValueError):
        return float(default)


def resolve_collection_material_report(run_dir: Path, run_manifest: dict[str, Any]) -> Path | None:
    for candidate in _manifest_sibling_reports(run_manifest):
        if candidate.is_file():
            return candidate
    default = Path("repair_training") / "material" / "zip" / "material_distribution_report_v3.json"
    return default.resolve() if default.is_file() else None


def load_material_index(run_dir: Path, run_manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    manifest = _manifest_path(run_manifest)
    if manifest and manifest.is_file():
        return _index_manifest(manifest)
    output: dict[str, dict[str, Any]] = {}
    root = Path("repair_training") / "material" / "zip"
    for manifest_path in root.glob("*/damage_manifest.jsonl"):
        output.update(_index_manifest(manifest_path))
    return output


def compact_material_distribution(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile_counts": report.get("profile_counts", {}),
        "layer_counts": report.get("layer_counts", {}),
        "target_errors": report.get("target_errors", {}),
        "physical_complete_expected_counts": report.get("physical_complete_expected_counts", {}),
    }


def _manifest_sibling_reports(run_manifest: dict[str, Any]) -> list[Path]:
    manifest = _manifest_path(run_manifest)
    if manifest and manifest.is_file():
        return sorted(manifest.parent.glob("material_distribution_report*.json"))
    return []


def _manifest_path(run_manifest: dict[str, Any]) -> Path | None:
    inputs = run_manifest.get("inputs") if isinstance(run_manifest.get("inputs"), dict) else {}
    for key in ("manifest_abs", "manifest"):
        raw = str(inputs.get(key) or "").strip()
        if raw:
            return Path(raw).resolve()
    return None


def _index_manifest(path: Path) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return output
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            sample_id = str(row.get("sample_id") or "")
            if not sample_id:
                continue
            derivation = row.get("source_derivation") if isinstance(row.get("source_derivation"), dict) else {}
            output[sample_id] = {
                "damage_profile": row.get("damage_profile") or row.get("profile"),
                "profile_layer": row.get("profile_layer") or row.get("damage_layer") or derivation.get("layer"),
                "damage_layer": row.get("damage_layer") or derivation.get("layer"),
                "physical_complete_expected": row.get("physical_complete_expected"),
            }
    return output
