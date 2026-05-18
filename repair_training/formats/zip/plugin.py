from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import random

from repair_training.core.plugin import TrainingFeatureSpec, TrainingFormatPlugin, TrainingLabelSchema
from sunpack.repair.policy.adapters.damage import get_damage_analysis_adapter
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
    "eocd.cd_size",
    "eocd.entry_count",
    "central_directory.header",
    "central_directory.flags",
    "central_directory.method",
    "central_directory.filename",
    "central_directory.extra",
    "central_directory.extra_length",
    "central_directory.local_header_offset",
    "central_directory.crc",
    "central_directory.compressed_size",
    "central_directory.metadata",
    "central_directory.external_attributes",
    "local_header.header",
    "local_header.signature",
    "local_header.flags",
    "local_header.method",
    "local_header.filename",
    "local_header.extra",
    "local_header.extra_length",
    "local_header.crc",
    "local_header.compressed_size",
    "local_header.metadata",
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
    "zip_extra_field_local_header_bad",
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
    "compound_sfx_cd_offset_only",
    "compound_sfx_cd_offset_payload_partial",
    "compound_sfx_cd_offset_split_only",
    "compound_sfx_cd_offset_with_payload_no_local_header",
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
        state_value_feature_spec=state_value_feature_spec,
        lightgbm_params=lightgbm_params,
        postprocess_damage_prediction=postprocess_damage_prediction,
        action_label=action_label,
        damage_eval_profile_plan=damage_eval_profile_plan,
        generate_damage_eval_records=generate_damage_eval_records,
        damage_eval_metadata=damage_eval_metadata,
        diagnostic_feature_groups=diagnostic_feature_groups,
        diagnostic_profile_pairs=diagnostic_profile_pairs,
        diagnostic_focus_labels=diagnostic_focus_labels,
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
        include_prefixes=("knowledge_payload.",),
        ignore_prefixes=(
            "knowledge_payload.source.input.path",
            "knowledge_payload.archive_state.state",
        ),
    )


def action_feature_spec() -> TrainingFeatureSpec:
    return TrainingFeatureSpec(
        include_prefixes=("action_type", "candidate_snapshot.", "damage_analysis.", "current_recovery."),
        categorical_paths=(
            "action_type",
            "candidate_snapshot.action_type",
            "candidate_snapshot.module_name",
            "candidate_snapshot.module_family",
            "candidate_snapshot.status",
            "current_recovery.status",
            "current_recovery.decision_hint",
        ),
        ignore_prefixes=(
            "candidate_snapshot.candidate_id",
            "candidate_snapshot.patch_digest",
            "candidate_snapshot.patch_depth",
            "candidate_snapshot.patch_count",
            "candidate_snapshot.last_patch_module",
            "candidate_snapshot.has_archive_state_plan",
            "candidate_snapshot.branchable",
            "candidate_snapshot.metadata.recovery_",
            "candidate_snapshot.metadata.score_source",
            "candidate_snapshot.metadata.verification_summary",
            "candidate_snapshot.metadata.status",
            "candidate_snapshot.metadata.candidate_status",
            "candidate_snapshot.metadata.recovery_status",
            "candidate_snapshot.recovery_",
            "candidate_snapshot.recovery_snapshot.state_digest",
            "candidate_snapshot.recovery_snapshot.extraction.archive",
            "candidate_snapshot.recovery_snapshot.extraction.out_dir",
            "candidate_snapshot.recovery_snapshot.verification.files",
            "candidate_snapshot.validation_summary.recovery_",
            "candidate_snapshot.workspace_paths",
            "candidate_snapshot.repaired_input.path",
        ),
    )


def state_value_feature_spec() -> TrainingFeatureSpec:
    return TrainingFeatureSpec(
        include_prefixes=(
            "format",
            "round_index",
            "patch_depth",
            "damage_analysis.",
            "current_recovery.",
            "best_seen_recovery.",
            "parent_recovery.",
            "repair_history.",
            "graph_summary.",
            "frontier_summary.",
            "branch_status",
        ),
        categorical_paths=(
            "format",
            "branch_status",
            "current_recovery.status",
            "current_recovery.decision_hint",
            "current_recovery.metadata.score_source",
            "current_recovery.extraction.failure_kind",
            "current_recovery.extraction.failure_stage",
            "best_seen_recovery.status",
            "parent_recovery.status",
        ),
        ignore_prefixes=(
            "current_recovery.state_digest",
            "best_seen_recovery.state_digest",
            "parent_recovery.state_digest",
            "current_recovery.extraction.archive",
            "current_recovery.extraction.out_dir",
            "current_recovery.verification.files",
            "candidate_summary.patch_digest",
            "graph_summary.node_ids",
            "frontier_summary.edge_ids",
        ),
    )


def lightgbm_params(model_type: str) -> dict[str, Any]:
    if model_type == "step_action":
        return {
            "objective": "lambdarank",
            "n_estimators": 80,
            "learning_rate": 0.04,
            "num_leaves": 15,
            "min_child_samples": 2,
            "subsample": 0.9,
            "colsample_bytree": 0.9,
        }
    if model_type == "normal_structure":
        return {
            "objective": "binary",
            "n_estimators": 90,
            "learning_rate": 0.04,
            "num_leaves": 31,
            "min_child_samples": 2,
            "subsample": 0.9,
            "colsample_bytree": 0.9,
        }
    if model_type == "step_value":
        return {
            "objective": "regression",
            "n_estimators": 100,
            "learning_rate": 0.04,
            "num_leaves": 31,
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
    if "policy_prior_label" in row:
        return int(max(0, min(31, round(_float(row.get("policy_prior_label"))))))
    current = _recovery_score(row.get("current_recovery"))
    label = 8
    if row.get("is_best_action"):
        label = 28
    if action == "stop":
        label = 28 if current >= 0.95 else 6
    elif action == "undo":
        label = max(label, 14)
    elif action == "module":
        if _is_recovery_candidate(row):
            label = max(label, 18)
        if _is_salvage_or_rebuild_candidate(row):
            label = max(label, 20)
    return int(max(0, min(31, label)))


def _recovery_score(value: Any) -> float:
    if isinstance(value, dict):
        return _float(value.get("score"))
    return _float(value)


def _state_value_score(*values: Any, default: float = 0.0) -> float:
    for value in values:
        if isinstance(value, dict):
            for key in ("reachable_recovery_value", "score", "value"):
                if key in value:
                    return max(0.0, min(1.0, _float(value.get(key))))
        elif value not in (None, ""):
            return max(0.0, min(1.0, _float(value)))
    return max(0.0, min(1.0, _float(default)))


def _is_recovery_candidate(row: dict[str, Any]) -> bool:
    snapshot = row.get("candidate_snapshot") if isinstance(row.get("candidate_snapshot"), dict) else {}
    validation = snapshot.get("validation_summary") if isinstance(snapshot.get("validation_summary"), dict) else {}
    return bool(validation.get("accepted")) or _is_salvage_or_rebuild_candidate(row)


def _is_salvage_or_rebuild_candidate(row: dict[str, Any]) -> bool:
    snapshot = row.get("candidate_snapshot") if isinstance(row.get("candidate_snapshot"), dict) else {}
    metadata = snapshot.get("metadata") if isinstance(snapshot.get("metadata"), dict) else {}
    tokens = " ".join(
        str(value or "")
        for value in (
            snapshot.get("module_name"),
            snapshot.get("module"),
            snapshot.get("module_family"),
            snapshot.get("last_patch_module"),
            metadata.get("last_patch_module"),
            metadata.get("module_name"),
            row.get("candidate_id"),
        )
    ).lower()
    return any(token in tokens for token in ("salvage", "rebuild", "carrier_crop", "deep_recovery"))


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


def diagnostic_focus_labels() -> list[str]:
    return [
        "field:payload.compressed_data",
        "field:local_header.crc",
        "field:local_header.compressed_size",
        "field:local_header.flags",
        "field:sfx_prefix.bytes",
        "field:split_volume.missing_range",
    ]


def diagnostic_profile_pairs() -> list[tuple[str, str]]:
    return [
        ("compound_sfx_cd_offset_split_only", "compound_sfx_cd_offset_payload_partial"),
        ("compound_sfx_cd_offset_split_only", "compound_sfx_cd_offset_with_payload_no_local_header"),
        ("zip_sfx_cd_damage", "compound_sfx_cd_offset_only"),
        ("zip_sfx_cd_damage", "compound_sfx_cd_offset_payload_partial"),
        ("zip_split_missing_middle_volume", "compound_sfx_cd_offset_split_only"),
        ("compound_descriptor_fake_span_flags_cd_offset", "zip_data_descriptor_cd_conflict"),
        ("compound_descriptor_fake_span_flags_cd_offset", "zip_data_descriptor_payload_bad"),
        ("compound_comment_eocd_count_cd_rebuild", "zip_comment_overlap_eocd_shifted"),
        ("compound_comment_eocd_count_cd_rebuild", "compound_boundary_drop_cd_payload_bad"),
    ]


def diagnostic_feature_groups() -> dict[str, list[str]]:
    return {
        "graph_summary": [
            "knowledge_payload.format.zip.structure.graph.summary.",
            "knowledge_payload.format.zip.structure.summary.",
        ],
        "graph_violations": [
            "knowledge_payload.format.zip.structure.graph.violations.",
        ],
        "graph_explanations": [
            "knowledge_payload.format.zip.structure.graph.explanations.",
        ],
        "runtime_payload": [
            "knowledge_payload.format.zip.structure.runtime.payload_",
            "knowledge_payload.format.zip.structure.runtime.no_payload_",
        ],
        "normal_anomaly": [
            "knowledge_payload.format.zip.structure.anomaly.summary.",
            "knowledge_payload.format.zip.structure.anomaly.compact_attribution.",
        ],
        "extraction_entry_outcomes": [
            "knowledge_payload.extraction.entry_outcomes.",
            "knowledge_payload.format.zip.structure.runtime.extraction_entry_outcomes.",
        ],
        "verification_coverage": [
            "knowledge_payload.verification.coverage_breakdown.",
            "knowledge_payload.format.zip.structure.runtime.verification_coverage_breakdown.",
        ],
    }


class CounterProxy:
    def __init__(self, values: dict[str, int]):
        self.values = values

    def __getitem__(self, key: str) -> int:
        return int(self.values.get(str(key), 0))


def zip_module_family(module_name: str) -> str:
    module = str(module_name or "")
    for family, modules in ZIP_MODULE_FAMILIES.items():
        if module in modules:
            return family
    return "zip_other"


def postprocess_damage_prediction(raw_scores: dict[str, Any]) -> dict[str, Any]:
    scores = _score_map(raw_scores)
    adapter = get_damage_analysis_adapter("zip")
    threshold = raw_scores.get("threshold") if isinstance(raw_scores, dict) else None
    result = adapter.postprocess_scores(  # type: ignore[union-attr]
        scores,
        raw_scores.get("thresholds") if isinstance(raw_scores, dict) else None,
        threshold_override=_float(threshold) if threshold is not None else None,
    )
    return result.to_dict()


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

