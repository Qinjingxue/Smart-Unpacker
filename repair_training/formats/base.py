from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class TrainingFeatureSpec:
    include_prefixes: tuple[str, ...] = ()
    numeric_paths: tuple[str, ...] = ()
    categorical_paths: tuple[str, ...] = ()
    ignore_prefixes: tuple[str, ...] = ()
    ignore_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class TrainingLabelSchema:
    labels: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TrainingFormatPlugin:
    format_name: str
    default_run_name: str
    default_collection_budget: dict[str, Any] = field(default_factory=dict)
    default_distribution: Path | None = None
    model_output_subdir: Path | str = ""
    resolve_material_manifest: Callable[[Any], Path | None] | None = None
    build_material: Callable[[Any], int] | None = None
    collection_record_context: Callable[[dict[str, Any]], dict[str, Any]] | None = None
    oracle_label: Callable[[Any, dict[str, Any]], dict[str, Any]] | None = None
    resolve_collection_material_report: Callable[[Path, dict[str, Any]], Path | None] | None = None
    load_material_index: Callable[[Path, dict[str, Any]], dict[str, dict[str, Any]]] | None = None
    compact_material_distribution: Callable[[dict[str, Any]], dict[str, Any]] | None = None
    collection_report_sections: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None
    damage_label_schema: Callable[[], TrainingLabelSchema | dict[str, Any]] | None = None
    damage_feature_spec: Callable[[], TrainingFeatureSpec | dict[str, Any]] | None = None
    damage_eval_profile_plan: Callable[[int, int], list[str]] | None = None
    generate_damage_eval_records: Callable[[str | Path, str | Path, int, int, list[str]], list[dict[str, Any]]] | None = None
    damage_eval_metadata: Callable[[], dict[str, Any]] | None = None
    diagnostic_feature_groups: Callable[[], dict[str, list[str]]] | None = None
    diagnostic_profile_pairs: Callable[[], list[tuple[str, str]]] | None = None
    diagnostic_focus_labels: Callable[[], list[str]] | None = None


def load_training_format_plugin(format_name: str) -> TrainingFormatPlugin:
    normalized = normalize_format_name(format_name)
    module_name = normalized.replace("-", "_")
    try:
        module = importlib.import_module(f"repair_training.formats.{module_name}.plugin")
    except ModuleNotFoundError as exc:
        raise SystemExit(
            f"Unsupported training format: {format_name}. "
            f"Missing repair_training.formats.{module_name}.plugin"
        ) from exc
    factory = getattr(module, "get_training_plugin", None)
    if not callable(factory):
        raise SystemExit(f"Training format plugin has no get_training_plugin(): {module.__name__}")
    plugin = factory()
    if not isinstance(plugin, TrainingFormatPlugin):
        raise SystemExit(f"Invalid training format plugin returned by {module.__name__}")
    return plugin


def normalize_format_name(format_name: str) -> str:
    value = str(format_name or "").strip().lower().lstrip(".")
    aliases = {
        "7zip": "seven_zip",
        "7z": "seven_zip",
        "zip": "zip",
    }
    return aliases.get(value, value)
