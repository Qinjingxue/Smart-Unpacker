from __future__ import annotations

import subprocess
import sys
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
