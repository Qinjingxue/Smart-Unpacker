from __future__ import annotations

import subprocess
import sys
import json
from pathlib import Path
from typing import Any

from repair_training.core.plugin import TrainingFormatPlugin
from sunpack.repair.context import zip_route_evidence_flags


FORMAT_NAME = "zip"
PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_DISTRIBUTION = PACKAGE_ROOT / "distributions" / "damage_distribution_zip_root_transition_v3.json"


def get_training_plugin() -> TrainingFormatPlugin:
    return TrainingFormatPlugin(
        format_name=FORMAT_NAME,
        default_run_name="zip_runtime_graph",
        default_feature_view="runtime_minimal_native_validation",
        default_target="root_transition_return_v1",
        default_sample_weight_mode="root_transition_v1",
        default_collection_budget={
            "workers": 6,
            "max_rounds": 6,
            "max_states": 20,
            "branch_top_k": 5,
            "root_branch_top_k": 5,
            "materialize_top_k": 8,
        },
        default_distribution=DEFAULT_DISTRIBUTION,
        model_output_subdir=Path("models") / "zip_runtime_policy",
        collection_record_context=collection_record_context,
        resolve_collection_material_report=resolve_collection_material_report,
        load_material_index=load_material_index,
        compact_material_distribution=compact_material_distribution,
        analyze_collection=_analyze_collection,
        analyze_training=_analyze_training,
    )


def _analyze_collection(run_dir: Path) -> int | None:
    return subprocess.call([
        sys.executable,
        "-m",
        "repair_training.core.analyze_collection",
        "--run-dir",
        str(run_dir),
    ])


def _analyze_training(run_dir: Path, model_dir: Path) -> int | None:
    return subprocess.call([
        sys.executable,
        "-m",
        "repair_training.core.analyze_training",
        "--run-dir",
        str(run_dir),
        "--model-dir",
        str(model_dir),
    ])


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
