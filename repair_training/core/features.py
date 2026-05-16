from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from repair_training.core.datasets import action_query_id, group_sizes, sort_for_groups, split_rows, write_json
from repair_training.core.plugin import TrainingFeatureSpec, TrainingFormatPlugin, TrainingLabelSchema


FEATURE_SCHEMA_VERSION = 1
UNK = "<UNK>"


def build_feature_datasets(
    rows: list[dict[str, Any]],
    *,
    plugin: TrainingFormatPlugin,
    model_type: str,
    output_dir: str | Path,
) -> dict[str, Any]:
    model_type = normalize_model_type(model_type)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if model_type == "repair_action":
        rows = sort_for_groups(rows)
    splits = split_rows(rows)
    spec = feature_spec(plugin, model_type)
    label_schema = labels_for_plugin(plugin, model_type)
    if model_type == "damage_location":
        label_schema = filtered_damage_label_schema(rows, label_schema)
    schema = _fit_schema(splits["train"] or rows, spec=spec, model_type=model_type)
    schema["model_type"] = model_type
    schema["format"] = plugin.format_name
    schema["feature_schema_version"] = FEATURE_SCHEMA_VERSION
    schema["label_schema"] = label_schema
    write_json(output_dir / "feature_schema.json", schema)
    write_json(output_dir / ("action_schema.json" if model_type == "repair_action" else "label_schema.json"), label_schema)
    if model_type == "damage_location":
        write_json(output_dir / "observed_label_schema.json", {"labels": list(label_schema.get("labels") or []), "metadata": dict(label_schema.get("metadata", {}).get("observed") or {})})
        write_json(output_dir / "uncertain_label_schema.json", {"labels": list(label_schema.get("uncertain_labels") or []), "metadata": dict(label_schema.get("metadata", {}).get("uncertain") or {})})
    summary: dict[str, Any] = {"model_type": model_type, "format": plugin.format_name, "splits": {}}
    for split, split_rows_ in splits.items():
        if model_type == "repair_action":
            split_rows_ = sort_for_groups(split_rows_)
        x, y = transform_rows(split_rows_, schema=schema, plugin=plugin, model_type=model_type)
        np.savez_compressed(output_dir / f"{split}.npz", X=x, y=y)
        if model_type == "repair_action":
            groups = group_sizes(split_rows_, key_fn=action_query_id)
            (output_dir / f"group_{split}.txt").write_text("\n".join(str(item) for item in groups), encoding="utf-8")
        if model_type == "normal_structure":
            _write_normal_structure_meta(output_dir / f"meta_{split}.jsonl", split_rows_)
        summary["splits"][split] = {"rows": len(split_rows_), "features": int(x.shape[1]), "labels": int(y.shape[1]) if y.ndim > 1 else 1}
    if model_type == "damage_location":
        summary["label_summary"] = dict((label_schema.get("metadata") or {}).get("label_summary") or {})
    write_json(output_dir / "feature_summary.json", summary)
    return summary


def transform_rows(
    rows: list[dict[str, Any]],
    *,
    schema: dict[str, Any],
    plugin: TrainingFormatPlugin,
    model_type: str,
) -> tuple[np.ndarray, np.ndarray]:
    model_type = normalize_model_type(model_type)
    feature_names = list(schema.get("feature_names") or [])
    categorical_maps = {key: dict(value) for key, value in (schema.get("categorical_maps") or {}).items()}
    x = np.zeros((len(rows), len(feature_names)), dtype=np.float32)
    for row_index, row in enumerate(rows):
        flat = _feature_row(row, model_type=model_type)
        for col, name in enumerate(feature_names):
            if name in categorical_maps:
                x[row_index, col] = float(categorical_maps[name].get(str(flat.get(name) or UNK), categorical_maps[name].get(UNK, 0)))
            else:
                x[row_index, col] = _float(flat.get(name))
    if model_type == "damage_location":
        labels = list((schema.get("label_schema") or {}).get("labels") or [])
        uncertain_labels = list((schema.get("label_schema") or {}).get("uncertain_labels") or [])
        y = np.zeros((len(rows), len(labels) + len(uncertain_labels)), dtype=np.float32)
        label_index = {label: index for index, label in enumerate(labels)}
        uncertain_index = {label: len(labels) + index for index, label in enumerate(uncertain_labels)}
        for row_index, row in enumerate(rows):
            for label in damage_labels_for_row(row):
                if label in label_index:
                    y[row_index, label_index[label]] = 1.0
            for label in uncertain_labels_for_row(row):
                if label in uncertain_index:
                    y[row_index, uncertain_index[label]] = 1.0
        return x, y
    if model_type == "normal_structure":
        y = np.array([1.0 if _float(row.get("normal_label")) >= 0.5 else 0.0 for row in rows], dtype=np.float32)
        return x, y
    y = np.array([action_label(plugin, row) for row in rows], dtype=np.float32)
    return x, y


def feature_spec(plugin: TrainingFormatPlugin, model_type: str) -> TrainingFeatureSpec:
    model_type = normalize_model_type(model_type)
    raw = plugin.damage_feature_spec() if model_type == "damage_location" and plugin.damage_feature_spec else None
    if raw is None and model_type == "repair_action" and plugin.action_feature_spec:
        raw = plugin.action_feature_spec()
    if isinstance(raw, TrainingFeatureSpec):
        return raw
    if isinstance(raw, dict):
        return TrainingFeatureSpec(
            include_prefixes=tuple(raw.get("include_prefixes") or ()),
            numeric_paths=tuple(raw.get("numeric_paths") or ()),
            categorical_paths=tuple(raw.get("categorical_paths") or ()),
            ignore_prefixes=tuple(raw.get("ignore_prefixes") or ()),
            ignore_paths=tuple(raw.get("ignore_paths") or ()),
        )
    if model_type == "damage_location":
        return TrainingFeatureSpec(
            include_prefixes=("damage_analysis_input.",),
            ignore_prefixes=("damage_analysis_input.job.source_input.path", "damage_analysis_input.archive_state.state"),
        )
    if model_type == "normal_structure":
        return TrainingFeatureSpec(
            include_prefixes=(
                "query_type",
                "target_zone",
                "target_field",
                "target_node_kind",
                "source_node_kind",
                "relation_kind",
                "explanation_kind",
                "entry_index_bucket",
                "features.",
            ),
            categorical_paths=(
                "query_type",
                "target_zone",
                "target_field",
                "target_node_kind",
                "source_node_kind",
                "relation_kind",
                "explanation_kind",
                "entry_index_bucket",
            ),
            ignore_prefixes=("metadata.", "source_identity."),
            ignore_paths=(
                "normal_label",
                "features.candidate_source_delta_bucket",
                "features.violation_kind",
                "features.violation_severity",
            ),
        )
    return TrainingFeatureSpec(
        include_prefixes=("action_type", "candidate_snapshot.", "damage_analysis_target.", "current_recovery.", "next_recovery.", "recovery_delta"),
        categorical_paths=("action_type", "candidate_snapshot.module_name", "candidate_snapshot.action_type"),
        ignore_prefixes=("candidate_snapshot.patch_digest",),
    )


def labels_for_plugin(plugin: TrainingFormatPlugin, model_type: str) -> dict[str, Any]:
    model_type = normalize_model_type(model_type)
    if model_type == "damage_location" and plugin.damage_label_schema:
        raw = plugin.damage_label_schema()
        if isinstance(raw, TrainingLabelSchema):
            return {"labels": list(raw.labels), "metadata": dict(raw.metadata)}
        if isinstance(raw, dict):
            return {"labels": list(raw.get("labels") or []), "metadata": dict(raw.get("metadata") or {})}
    if model_type == "damage_location":
        return {"labels": ["family:unknown"], "metadata": {}}
    if model_type == "normal_structure":
        return {
            "labels": ["normal_label"],
            "metadata": {
                "kind": "binary_normal_structure",
                "positive_label": 1,
                "negative_label": 0,
            },
        }
    return {"labels": ["apply_patch", "undo_patch", "stop", "give_up"], "metadata": {"kind": "ranking_actions"}}


def filtered_damage_label_schema(rows: list[dict[str, Any]], label_schema: dict[str, Any]) -> dict[str, Any]:
    original_labels = list(label_schema.get("labels") or [])
    observed_counts = {label: 0 for label in original_labels}
    uncertain_counts = {label: 0 for label in original_labels}
    for row in rows:
        present = set(damage_labels_for_row(row))
        uncertain_present = set(uncertain_labels_for_row(row))
        for label in original_labels:
            if label in present:
                observed_counts[label] += 1
            if label in uncertain_present:
                uncertain_counts[label] += 1
    total = len(rows)
    active, observed_ignored, observed_priors = _active_label_split(original_labels, observed_counts, total)
    uncertain_active, uncertain_ignored, uncertain_priors = _active_label_split(original_labels, uncertain_counts, total)
    metadata = dict(label_schema.get("metadata") or {})
    metadata["original_labels"] = original_labels
    metadata["ignored_labels"] = observed_ignored
    metadata["uncertain_ignored_labels"] = uncertain_ignored
    metadata["route_priors"] = observed_priors
    metadata["uncertain_route_priors"] = uncertain_priors
    metadata["observed"] = _label_summary_payload(original_labels, active, observed_ignored, observed_counts, total)
    metadata["uncertain"] = _label_summary_payload(original_labels, uncertain_active, uncertain_ignored, uncertain_counts, total)
    metadata["label_summary"] = {
        "total_rows": total,
        "original_label_count": len(original_labels),
        "active_label_count": len(active),
        "uncertain_active_label_count": len(uncertain_active),
        "ignored_label_count": len(observed_ignored),
        "uncertain_ignored_label_count": len(uncertain_ignored),
        "all_negative_count": sum(1 for item in observed_ignored if item["reason"] == "all_negative"),
        "all_positive_count": sum(1 for item in observed_ignored if item["reason"] == "all_positive"),
        "uncertain_all_negative_count": sum(1 for item in uncertain_ignored if item["reason"] == "all_negative"),
        "uncertain_all_positive_count": sum(1 for item in uncertain_ignored if item["reason"] == "all_positive"),
    }
    metadata["label_positive_counts"] = {
        label: {
            "positive_count": int(observed_counts.get(label, 0)),
            "positive_ratio": float(observed_counts.get(label, 0) / total) if total else 0.0,
        }
        for label in original_labels
    }
    metadata["uncertain_label_positive_counts"] = {
        label: {
            "positive_count": int(uncertain_counts.get(label, 0)),
            "positive_ratio": float(uncertain_counts.get(label, 0) / total) if total else 0.0,
        }
        for label in original_labels
    }
    return {"labels": active, "uncertain_labels": uncertain_active, "metadata": metadata}


def _active_label_split(original_labels: list[str], counts: dict[str, int], total: int) -> tuple[list[str], list[dict[str, Any]], dict[str, float]]:
    active: list[str] = []
    ignored: list[dict[str, Any]] = []
    priors: dict[str, float] = {}
    for label in original_labels:
        positive = int(counts.get(label, 0))
        ratio = float(positive / total) if total else 0.0
        if positive == 0:
            ignored.append({
                "label": label,
                "reason": "all_negative",
                "positive_count": positive,
                "total_count": total,
                "positive_ratio": ratio,
            })
            continue
        if total and positive == total:
            ignored.append({
                "label": label,
                "reason": "all_positive",
                "positive_count": positive,
                "total_count": total,
                "positive_ratio": ratio,
            })
            priors[label] = ratio
            continue
        active.append(label)
    return active, ignored, priors


def _label_summary_payload(
    original_labels: list[str],
    active: list[str],
    ignored: list[dict[str, Any]],
    counts: dict[str, int],
    total: int,
) -> dict[str, Any]:
    return {
        "total_rows": total,
        "original_label_count": len(original_labels),
        "active_label_count": len(active),
        "ignored_label_count": len(ignored),
        "all_negative_count": sum(1 for item in ignored if item["reason"] == "all_negative"),
        "all_positive_count": sum(1 for item in ignored if item["reason"] == "all_positive"),
        "label_positive_counts": {
            label: {
                "positive_count": int(counts.get(label, 0)),
                "positive_ratio": float(counts.get(label, 0) / total) if total else 0.0,
            }
            for label in original_labels
        },
    }


def damage_labels_for_row(row: dict[str, Any]) -> list[str]:
    target = row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {}
    source = target.get("observed_labels") if isinstance(target.get("observed_labels"), list) else target.get("damage_labels")
    return _location_label_list(source)


def uncertain_labels_for_row(row: dict[str, Any]) -> list[str]:
    target = row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {}
    return _location_label_list(target.get("uncertain_labels") or [])


def oracle_damage_labels_for_row(row: dict[str, Any]) -> list[str]:
    target = row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {}
    return _location_label_list(target.get("damage_labels") or [])


def _location_label_list(raw: Any) -> list[str]:
    labels: list[str] = []
    for label in raw or []:
        text = str(label or "")
        if text.startswith(("zone:", "field:")):
            labels.append(text)
    return sorted(set(labels))


def damage_location_labels_from_target(target: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    for label in target.get("damage_labels") or []:
        text = str(label or "")
        if text.startswith(("zone:", "field:")):
            labels.append(text)
    for item in target.get("labels") or []:
        if not isinstance(item, dict):
            continue
        zone = item.get("zone") if isinstance(item.get("zone"), dict) else {}
        zone_label = _zone_label(zone)
        if zone_label:
            labels.append(f"zone:{zone_label}")
        field_label = _field_label(zone)
        if field_label:
            labels.append(f"field:{field_label}")
    return sorted(set(labels))


def _zone_label(zone: dict[str, Any]) -> str:
    path = str(zone.get("path") or "").lower()
    kind = str(zone.get("kind") or "").lower()
    if kind == "flag":
        return ""
    text = f"{kind}.{path}"
    if "sfx" in text or "prefix" in text or "carrier" in text:
        return "sfx_prefix"
    if "missing_volume" in text or "split" in text or "volume" in text:
        return "split_volume"
    if "zip64" in text:
        return "zip64"
    if "eocd" in text:
        return "eocd"
    if "central_directory" in text or "central.dir" in text:
        return "central_directory"
    if "local_header" in text or "local.header" in text:
        return "local_header"
    if "data_descriptor" in text or "descriptor" in text or "bit3" in text:
        return "data_descriptor"
    if "extra" in text:
        return "extra_field"
    if "payload" in text or "file_data" in text:
        return "payload"
    if "tail" in text or "comment" in text:
        return "tail"
    return ""


def _field_label(zone: dict[str, Any]) -> str:
    path = str(zone.get("path") or "").lower().replace("-", "_")
    kind = str(zone.get("kind") or "").lower()
    if kind == "flag" or not path:
        return ""
    path = path.replace("zip.", "")
    path = path.replace("central.dir", "central_directory")
    mapping = (
        ("eocd.entry_counts", "eocd.entry_count"),
        ("eocd.entry_count_total", "eocd.entry_count"),
        ("eocd.entry_count_disk", "eocd.entry_count"),
        ("eocd.cd_offset", "eocd.cd_offset"),
        ("eocd.comment_length", "eocd.comment_length"),
        ("eocd.comment", "eocd.comment"),
        ("central_directory.local_header_offset", "central_directory.local_header_offset"),
        ("central_directory.external_attributes", "central_directory.external_attributes"),
        ("central_directory.compressed_size", "central_directory.compressed_size"),
        ("central_directory.extra_length", "central_directory.extra_length"),
        ("central_directory.filename", "central_directory.filename"),
        ("central_directory.flags", "central_directory.flags"),
        ("central_directory.crc", "central_directory.crc"),
        ("central_directory.extra", "central_directory.extra"),
        ("local_header.compressed_size", "local_header.compressed_size"),
        ("local_header.extra_length", "local_header.extra_length"),
        ("local_header.extra_field", "local_header.extra"),
        ("local_header.filename", "local_header.filename"),
        ("local_header.flags", "local_header.flags"),
        ("local_header.crc", "local_header.crc"),
        ("local_header.extra", "local_header.extra"),
        ("data_descriptor.crc", "data_descriptor.crc"),
        ("data_descriptor.size", "data_descriptor.size"),
        ("data_descriptor", "data_descriptor.record"),
        ("local_payload", "payload.compressed_data"),
        ("payload_hash_mismatch", "payload.crc_region"),
        ("crc_error", "payload.crc_region"),
        ("checksum_error", "payload.crc_region"),
        ("payload", "payload.compressed_data"),
        ("extra.zip64.uncompressed_size", "zip64.uncompressed_size"),
        ("extra.zip64.length", "zip64.extra_length"),
        ("zip64.locator", "zip64.locator"),
        ("zip64.eocd", "zip64.eocd"),
        ("archive.tail", "tail.trailing_bytes"),
        ("tail", "tail.trailing_bytes"),
        ("trailing_junk", "tail.trailing_bytes"),
        ("sfx.prefix", "sfx_prefix.bytes"),
        ("missing_volume", "split_volume.missing_range"),
    )
    for needle, label in mapping:
        if needle in path:
            return label
    return ""


def action_label(plugin: TrainingFormatPlugin, row: dict[str, Any]) -> int:
    if plugin.action_label is not None:
        return int(plugin.action_label(row))
    value = _float(row.get("long_term_value"))
    return int(max(0, min(31, round((value + 1.0) * 10.0))))


def _fit_schema(rows: list[dict[str, Any]], *, spec: TrainingFeatureSpec, model_type: str) -> dict[str, Any]:
    flattened = [_feature_row(row, model_type=model_type) for row in rows]
    keys = sorted({key for row in flattened for key in row if _allowed(key, spec)})
    categorical = {key for key in keys if key in spec.categorical_paths}
    numeric = set(spec.numeric_paths)
    for key in keys:
        if key in categorical or key in numeric:
            continue
        values = [row.get(key) for row in flattened if row.get(key) not in (None, "")]
        if values and all(_is_number(value) for value in values):
            numeric.add(key)
        else:
            categorical.add(key)
    feature_names = sorted(numeric) + sorted(categorical)
    maps: dict[str, dict[str, int]] = {}
    for key in sorted(categorical):
        values = sorted({str(row.get(key) or UNK) for row in flattened})
        maps[key] = {UNK: 0, **{value: index + 1 for index, value in enumerate(value for value in values if value != UNK)}}
    return {
        "feature_names": feature_names,
        "numeric_features": sorted(numeric),
        "categorical_features": sorted(categorical),
        "categorical_maps": maps,
        "spec": {
            "include_prefixes": list(spec.include_prefixes),
            "numeric_paths": list(spec.numeric_paths),
            "categorical_paths": list(spec.categorical_paths),
            "ignore_prefixes": list(spec.ignore_prefixes),
            "ignore_paths": list(spec.ignore_paths),
        },
    }


def _write_normal_structure_meta(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            payload = {
                "query_type": row.get("query_type"),
                "target_field": row.get("target_field"),
                "target_zone": row.get("target_zone"),
                "candidate_kind": row.get("candidate_kind"),
                "candidate_source": row.get("candidate_source"),
                "normal_label": row.get("normal_label"),
            }
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def _feature_row(row: dict[str, Any], *, model_type: str) -> dict[str, Any]:
    model_type = normalize_model_type(model_type)
    if model_type == "damage_location":
        payload = row.get("damage_analysis_input") if isinstance(row.get("damage_analysis_input"), dict) else row
    elif model_type == "normal_structure":
        payload = {
            "query_type": row.get("query_type"),
            "target_zone": row.get("target_zone"),
            "target_field": row.get("target_field"),
            "target_node_kind": row.get("target_node_kind"),
            "source_node_kind": row.get("source_node_kind"),
            "relation_kind": row.get("relation_kind"),
            "explanation_kind": row.get("explanation_kind"),
            "entry_index_bucket": row.get("entry_index_bucket"),
            "features": row.get("features") if isinstance(row.get("features"), dict) else {},
        }
    else:
        payload = {
            "action_type": row.get("action_type"),
            "candidate_snapshot": row.get("candidate_snapshot") if isinstance(row.get("candidate_snapshot"), dict) else {},
            "damage_analysis_target": row.get("damage_analysis_target") if isinstance(row.get("damage_analysis_target"), dict) else {},
            "current_recovery": row.get("current_recovery") if isinstance(row.get("current_recovery"), dict) else {},
            "next_recovery": row.get("next_recovery") if isinstance(row.get("next_recovery"), dict) else {},
            "recovery_delta": row.get("recovery_delta"),
        }
    return flatten(payload)


def normalize_model_type(model_type: str) -> str:
    text = str(model_type or "").strip()
    if text == "damage_analysis":
        return "damage_location"
    return text


def flatten(value: Any, *, prefix: str = "") -> dict[str, Any]:
    output: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            output.update(flatten(item, prefix=child))
        return output
    if isinstance(value, (list, tuple, set)):
        output[f"{prefix}.count" if prefix else "count"] = len(value)
        dict_items = [item for item in value if isinstance(item, dict)]
        if dict_items:
            output.update(_flatten_dict_list_summary(dict_items, prefix=prefix))
            return output
        for item in value:
            if isinstance(item, (str, int, float, bool)):
                output[f"{prefix}.{_safe_token(item)}" if prefix else _safe_token(item)] = 1
        return output
    output[prefix] = value
    return output


def _flatten_dict_list_summary(items: list[dict[str, Any]], *, prefix: str = "") -> dict[str, Any]:
    output: dict[str, Any] = {}
    categorical_keys = ("kind", "type", "status", "field", "severity", "valid", "applies")
    numeric_keys = ("delta", "confidence", "size", "start", "end")
    for item in items:
        for key in categorical_keys:
            if key not in item:
                continue
            token = _safe_token(item.get(key))
            name = f"{prefix}.{key}.{token}" if prefix else f"{key}.{token}"
            output[name] = output.get(name, 0) + 1
        for key in numeric_keys:
            if key not in item or not _is_number(item.get(key)):
                continue
            value = _float(item.get(key))
            base = f"{prefix}.{key}" if prefix else key
            output[f"{base}.sum"] = output.get(f"{base}.sum", 0.0) + value
            output[f"{base}.min"] = value if f"{base}.min" not in output else min(output[f"{base}.min"], value)
            output[f"{base}.max"] = value if f"{base}.max" not in output else max(output[f"{base}.max"], value)
    for key in numeric_keys:
        base = f"{prefix}.{key}" if prefix else key
        if f"{base}.sum" in output:
            output[f"{base}.mean"] = output[f"{base}.sum"] / float(max(1, len(items)))
    return output


def load_feature_schema(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _allowed(key: str, spec: TrainingFeatureSpec) -> bool:
    if key in spec.ignore_paths:
        return False
    if any(key.startswith(prefix) for prefix in spec.ignore_prefixes):
        return False
    if spec.include_prefixes and not any(key == prefix or key.startswith(prefix) for prefix in spec.include_prefixes):
        return False
    return True


def _safe_token(value: Any) -> str:
    text = str(value or "").strip()
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text)[:80] or UNK


def _float(value: Any) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _is_number(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False
