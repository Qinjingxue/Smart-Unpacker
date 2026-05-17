from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from repair_training.core.plugin import TrainingFeatureSpec, TrainingFormatPlugin, TrainingLabelSchema
from repair_training.taxonomy import SEVEN_ZIP_DAMAGE_FAMILIES


FORMAT_NAME = "seven_zip"
PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_DISTRIBUTION = PACKAGE_ROOT / "distributions" / "damage_distribution_seven_zip_root_transition_v2.json"


def get_training_plugin() -> TrainingFormatPlugin:
    return TrainingFormatPlugin(
        format_name=FORMAT_NAME,
        default_run_name="seven_zip_policy_lab",
        default_collection_budget={
            "workers": 6,
            "max_rounds": 6,
            "max_states": 20,
            "branch_top_k": 5,
            "root_branch_top_k": 5,
            "materialize_top_k": 8,
        },
        default_distribution=DEFAULT_DISTRIBUTION,
        model_output_subdir=Path("models") / "seven_zip_policy_lab",
        collection_record_context=collection_record_context,
        resolve_collection_material_report=resolve_collection_material_report,
        load_material_index=load_material_index,
        compact_material_distribution=compact_material_distribution,
        collection_report_sections=collection_report_sections,
        damage_label_schema=damage_label_schema,
        damage_feature_spec=damage_feature_spec,
        action_feature_spec=action_feature_spec,
        lightgbm_params=lightgbm_params,
        action_label=action_label,
        diagnostic_feature_groups=diagnostic_feature_groups,
        diagnostic_profile_pairs=diagnostic_profile_pairs,
        diagnostic_focus_labels=diagnostic_focus_labels,
    )


def damage_label_schema() -> TrainingLabelSchema:
    route_labels = (
        "route:next_header_crc_bad",
        "route:stream_crc_bad",
        "route:encoded_header_present",
        "route:split_sidecars_available",
        "route:password_required",
    )
    return TrainingLabelSchema(
        labels=tuple(sorted(f"family:{family}" for family in SEVEN_ZIP_DAMAGE_FAMILIES)) + route_labels,
        metadata={"taxonomy": "seven_zip", "schema_version": 1},
    )


def damage_feature_spec() -> TrainingFeatureSpec:
    return TrainingFeatureSpec(
        include_prefixes=("format", "runtime_context.", "diagnosis.", "repair_history."),
        categorical_paths=(
            "format",
            "runtime_context.analysis_summary.format",
            "runtime_context.archive_authentication.password_required",
            "runtime_context.extraction_summary.failure_stage",
            "runtime_context.extraction_summary.failure_kind",
            "runtime_context.verification_summary.decision_hint",
        ),
        ignore_prefixes=("runtime_context.archive_state.state", "job.source_input.path"),
    )


def action_feature_spec() -> TrainingFeatureSpec:
    return TrainingFeatureSpec(
        include_prefixes=("action_type", "candidate_snapshot.", "damage_analysis_target.", "current_recovery."),
        categorical_paths=(
            "action_type",
            "candidate_snapshot.action_type",
            "candidate_snapshot.module_name",
            "current_recovery.status",
            "current_recovery.decision_hint",
        ),
        ignore_prefixes=(
            "candidate_snapshot.patch_digest",
            "candidate_snapshot.patch_depth",
            "candidate_snapshot.patch_count",
            "candidate_snapshot.last_patch_module",
            "candidate_snapshot.has_archive_state_plan",
            "candidate_snapshot.branchable",
            "candidate_snapshot.recovery_",
            "candidate_snapshot.recovery_snapshot",
            "candidate_snapshot.verification_summary",
            "candidate_snapshot.metadata.recovery_",
            "candidate_snapshot.metadata.verification_summary",
            "candidate_snapshot.metadata.score_source",
        ),
    )


def lightgbm_params(model_type: str) -> dict[str, Any]:
    if model_type == "repair_action":
        return {"n_estimators": 60, "num_leaves": 15, "min_child_samples": 2}
    return {"n_estimators": 50, "num_leaves": 15, "min_child_samples": 2}


def action_label(row: dict[str, Any]) -> int:
    value = float(row.get("long_term_value") or 0.0)
    return int(max(0, min(31, round((value + 1.0) * 10.0))))


def diagnostic_focus_labels() -> list[str]:
    return [
        "route:next_header_crc_bad",
        "route:stream_crc_bad",
        "route:encoded_header_present",
        "route:split_sidecars_available",
        "route:password_required",
    ]


def diagnostic_profile_pairs() -> list[tuple[str, str]]:
    return []


def diagnostic_feature_groups() -> dict[str, list[str]]:
    return {
        "runtime_context": ["runtime_context."],
        "analysis": ["runtime_context.analysis_summary."],
        "extraction": ["runtime_context.extraction_summary."],
        "verification": ["runtime_context.verification_summary."],
    }


def collection_record_context(record: dict[str, Any]) -> dict[str, Any]:
    structure = dict(record.get("seven_zip_structure_features") or {})
    tags = [str(item) for item in record.get("seven_zip_container_tags") or [] if str(item)]
    route_flags = _dedupe([
        *[str(item) for item in record.get("runtime_damage_flags") or [] if str(item)],
        *[str(item) for item in record.get("damage_flags") or [] if str(item)],
        *[str(item) for item in structure.get("route_evidence_flags") or [] if str(item)],
    ])
    profile = str(record.get("damage_profile") or record.get("profile") or "")
    source_derivation = dict(record.get("source_derivation") or {})
    password = _record_password(record)
    archive_payload: dict[str, Any] = {
        "format": "7z",
        "password_present": bool(password),
    }
    if password:
        archive_payload["password"] = password
    return {
        "payloads": {
            "archive": archive_payload,
            "format.7z": {
                "structure": structure,
                "container_tags": tags,
                "route_evidence_flags": route_flags,
            },
            "source": {"profile": profile, "derivation": source_derivation},
            "training": {"sample_id": str(record.get("sample_id") or ""), "damage_profile": profile},
        },
        "flags": {"format.7z.route_evidence": route_flags, "repair.damage": route_flags},
    }


def resolve_collection_material_report(run_dir: Path, run_manifest: dict[str, Any]) -> Path | None:
    for candidate in _manifest_sibling_reports(run_manifest):
        if candidate.is_file():
            return candidate
    default = Path("repair_training") / "material" / "seven_zip" / "material_distribution_report_seven_zip_v2.json"
    return default.resolve() if default.is_file() else None


def load_material_index(run_dir: Path, run_manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    manifest = _manifest_path(run_manifest)
    return _index_manifest(manifest) if manifest and manifest.is_file() else {}


def compact_material_distribution(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile_counts": report.get("profile_counts", {}),
        "layer_counts": report.get("compound_profile_counts") or report.get("layer_counts", {}),
        "expected_min_steps_counts": report.get("expected_min_steps_counts", {}),
        "physical_complete_expected_counts": report.get("physical_complete_expected_counts", {}),
        "clean_variant_coverage": report.get("clean_variant_coverage", {}),
        "damaged_container_presence_counts": report.get("damaged_container_presence_counts", {}),
        "damaged_variant_coverage": {
            "compression_methods": (report.get("damaged_variant_coverage") or {}).get("compression_methods", {}),
            "compression_levels": (report.get("damaged_variant_coverage") or {}).get("compression_levels", {}),
            "profile_variant_warnings": (report.get("damaged_variant_coverage") or {}).get("profile_variant_warnings", {}),
        },
    }


def collection_report_sections(material_distribution: dict[str, Any]) -> list[dict[str, Any]]:
    clean = material_distribution.get("clean_variant_coverage") if isinstance(material_distribution.get("clean_variant_coverage"), dict) else {}
    damaged = material_distribution.get("damaged_container_presence_counts") if isinstance(material_distribution.get("damaged_container_presence_counts"), dict) else {}
    steps = material_distribution.get("expected_min_steps_counts") if isinstance(material_distribution.get("expected_min_steps_counts"), dict) else {}
    sections: list[dict[str, Any]] = []
    if clean:
        sections.append({
            "title": "7z Clean Variant Coverage",
            "headers": ["Metric", "Value"],
            "rows": [
                ["Variants", clean.get("variant_count", 0)],
                ["Methods", json.dumps(clean.get("compression_methods", {}), ensure_ascii=False, sort_keys=True)],
                ["Levels", json.dumps(clean.get("compression_levels", {}), ensure_ascii=False, sort_keys=True)],
                ["Split", json.dumps(clean.get("split_counts", {}), ensure_ascii=False, sort_keys=True)],
                ["Encrypted", json.dumps(clean.get("encrypted_counts", {}), ensure_ascii=False, sort_keys=True)],
                ["SFX", json.dumps(clean.get("sfx_counts", {}), ensure_ascii=False, sort_keys=True)],
                ["Encoded Header", json.dumps(clean.get("encoded_header_counts", {}), ensure_ascii=False, sort_keys=True)],
                ["Warnings", json.dumps(clean.get("warnings", {}), ensure_ascii=False, sort_keys=True)],
            ],
        })
    if damaged or steps:
        sections.append({
            "title": "7z Damaged Coverage",
            "headers": ["Metric", "Value"],
            "rows": [
                ["Container presence", json.dumps(damaged, ensure_ascii=False, sort_keys=True)],
                ["Expected min steps", json.dumps(steps, ensure_ascii=False, sort_keys=True)],
                ["Profile variant warnings", json.dumps(((material_distribution.get("damaged_variant_coverage") or {}).get("profile_variant_warnings", {})), ensure_ascii=False, sort_keys=True)],
            ],
        })
    return sections


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


def _index_manifest(path: Path | None) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    if path is None or not path.is_file():
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


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        if value and value not in output:
            output.append(value)
    return output


def _record_password(record: dict[str, Any]) -> str | None:
    for value in (
        record.get("password"),
        (record.get("damaged_input") or {}).get("password") if isinstance(record.get("damaged_input"), dict) else None,
        (record.get("clean_input") or {}).get("password") if isinstance(record.get("clean_input"), dict) else None,
    ):
        text = str(value or "")
        if text:
            return text
    return None
