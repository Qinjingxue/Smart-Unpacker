from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any


WORLD_SEMANTICS = "masked_archive_knowledge_v1"
WORLD_FIELD_INDEX = "world_field_index.json"

MASK_TOKEN = "<MASKED>"
MISSING_TOKEN = "<MISSING>"

_LEAK_TOKENS = (
    "path",
    "filepath",
    "filename",
    "sha",
    "hash",
    "digest",
    "uuid",
    "guid",
    "tmp",
    "temp",
    "workspace",
    "out_dir",
    "data_b64",
    "blob",
    "bytes",
)
_IGNORE_PREFIXES = (
    "source.input.path",
    "archive_state.state",
)


def world_payload_from_row(row: dict[str, Any]) -> dict[str, Any]:
    payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else row
    return payload if isinstance(payload, dict) else {}


def flatten_world_payload(payload: dict[str, Any]) -> dict[str, Any]:
    raw_flat = _flatten(payload)
    flat = dict(raw_flat)
    flat.update(_complex_summaries(payload))
    flat.update(_complex_relation_fields(payload))
    flat.update(_relation_fields(raw_flat))
    return {
        path: value
        for path, value in flat.items()
        if is_trainable_world_field(path, value)
    }


def is_trainable_world_field(path: str, value: Any) -> bool:
    text = str(path or "")
    lower = text.lower()
    if not text or any(lower == prefix or lower.startswith(prefix + ".") for prefix in _IGNORE_PREFIXES):
        return False
    if any(token in lower for token in _LEAK_TOKENS):
        return False
    if value is None:
        return False
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return math.isfinite(float(value))
    if isinstance(value, str):
        return 0 < len(value) <= 96
    return False


def value_type(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "numeric"
    return "categorical"


def world_field_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        if row.get("row_type") == "world_field_masked" and row.get("field_path"):
            output.append(dict(row))
            continue
        payload = world_payload_from_row(row)
        flat = flatten_world_payload(payload)
        for field_path in sorted(flat):
            value = flat[field_path]
            context = mask_field_group(flat, field_path)
            row_type = value_type(value)
            item = {
                "row_type": "world_field_masked",
                "sample_id": row.get("sample_id") or row.get("episode_id"),
                "state_digest": row.get("state_digest"),
                "source_identity": row.get("source_identity") if isinstance(row.get("source_identity"), dict) else {},
                "field_path": field_path,
                "value_type": row_type,
                "target_value": value,
                "target_numeric": float(value) if row_type == "numeric" else None,
                "target_category": _category(value),
                "context": context,
            }
            output.append(item)
    return output


def mask_field_group(flat: dict[str, Any], field_path: str) -> dict[str, Any]:
    leaf = field_path.rsplit(".", 1)[-1]
    parent = field_path.rsplit(".", 1)[0] if "." in field_path else ""
    masked: dict[str, Any] = {}
    for path, value in flat.items():
        if path == field_path:
            continue
        same_leaf = path.rsplit(".", 1)[-1] == leaf
        same_parent_summary = parent and path.startswith(parent + ".") and _related_leaf(path.rsplit(".", 1)[-1], leaf)
        related_relation = path.startswith("relations.") and _relation_mentions_target(path, field_path, leaf, parent)
        related_summary = path.startswith("summary.") and _summary_mentions_target(path, field_path, leaf, parent)
        if same_leaf or same_parent_summary or related_relation or related_summary:
            continue
        masked[path] = value
    masked["__masked_field_path"] = field_path
    masked["__masked_field_leaf"] = leaf
    masked["__masked_field_namespace"] = namespace_for_field(field_path)
    return masked


def row_for_inference(payload: dict[str, Any], field_path: str) -> dict[str, Any] | None:
    flat = flatten_world_payload(payload)
    return row_for_flat_world_payload(flat, field_path)


def row_for_flat_world_payload(flat: dict[str, Any], field_path: str) -> dict[str, Any] | None:
    if field_path not in flat:
        return None
    value = flat[field_path]
    return {
        "row_type": "world_field_masked",
        "field_path": field_path,
        "value_type": value_type(value),
        "target_value": value,
        "target_numeric": float(value) if value_type(value) == "numeric" else None,
        "target_category": _category(value),
        "context": mask_field_group(flat, field_path),
    }


def namespace_for_field(field_path: str) -> str:
    parts = [part for part in str(field_path or "").split(".") if part]
    if len(parts) >= 3:
        return ".".join(parts[:3])
    if len(parts) >= 2:
        return ".".join(parts[:2])
    return parts[0] if parts else ""


def safe_field_name(field_path: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(field_path or "field")).strip("._-")
    return text[:120] or "field"


def load_world_index(model_dir: str | Path) -> dict[str, Any]:
    path = Path(model_dir) / WORLD_FIELD_INDEX
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def world_summary(scores: dict[str, float], *, top_k: int = 12) -> dict[str, Any]:
    ranked = sorted(
        ((field, score) for field, score in scores.items() if float(score or 0.0) > 0.0),
        key=lambda item: item[1],
        reverse=True,
    )
    top = [{"field_path": field, "score": float(score), "namespace": namespace_for_field(field)} for field, score in ranked[:top_k]]
    namespace_scores: dict[str, float] = {}
    namespace_counts: dict[str, int] = {}
    for field, score in scores.items():
        namespace = namespace_for_field(field)
        namespace_scores[namespace] = namespace_scores.get(namespace, 0.0) + float(score)
        namespace_counts[namespace] = namespace_counts.get(namespace, 0) + 1
    return {
        "max_anomaly": float(ranked[0][1]) if ranked else 0.0,
        "mean_topk_anomaly": float(sum(score for _, score in ranked[:top_k]) / max(1, min(top_k, len(ranked)))) if ranked else 0.0,
        "top_fields": top,
        "namespace_scores": {
            key: namespace_scores[key] / max(1, namespace_counts.get(key, 1))
            for key in sorted(namespace_scores)
        },
    }


def world_field_rank_weight(field_path: str) -> float:
    text = str(field_path or "").lower()
    if not text:
        return 0.0
    if text.startswith("source.") or text.startswith("archive.password"):
        return 0.0
    if text.startswith("relations.same_leaf.password"):
        return 0.0
    if text.endswith(".format") or text.endswith(".schema_version"):
        return 0.0
    if text.endswith(".archive_readable"):
        return 0.0
    generic_count_suffixes = (
        ".edges.count",
        ".nodes.count",
        ".explanations.count",
        ".violations.count",
        ".edge_count",
        ".node_count",
        ".violation_count",
    )
    if text.endswith(generic_count_suffixes):
        return 0.15
    if ".structure.graph." in text or text.startswith("summary.format.zip.structure.graph"):
        return 1.0
    if text.startswith(("extraction.", "verification.", "relations.", "summary.")):
        return 0.7
    if text.startswith("format.zip."):
        return 0.8
    return 0.3


def _flatten(value: Any, *, prefix: str = "") -> dict[str, Any]:
    output: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            output.update(_flatten(item, prefix=child))
        return output
    if isinstance(value, (list, tuple, set)):
        output[f"{prefix}.count" if prefix else "count"] = len(value)
        return output
    output[prefix] = value
    return output


def _complex_summaries(value: Any, *, prefix: str = "") -> dict[str, Any]:
    output: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            output.update(_complex_summaries(item, prefix=child))
        return output
    if not isinstance(value, (list, tuple, set)):
        return output
    items = list(value)
    base = f"summary.{prefix}" if prefix else "summary.root_list"
    output[f"{base}.count"] = len(items)
    dict_items = [item for item in items if isinstance(item, dict)]
    if dict_items:
        output.update(_dict_list_summaries(dict_items, base=base))
        return output
    scalars = [item for item in items if isinstance(item, (str, int, float, bool))]
    if scalars:
        output.update(_scalar_list_summaries(scalars, base=base))
    return output


def _dict_list_summaries(items: list[dict[str, Any]], *, base: str) -> dict[str, Any]:
    output: dict[str, Any] = {}
    by_key: dict[str, list[Any]] = {}
    for item in items:
        flat_item = _flatten(item)
        for key, value in flat_item.items():
            if is_trainable_world_field(key, value):
                by_key.setdefault(key, []).append(value)
    for key, values in by_key.items():
        field = f"{base}.{key}"
        output[f"{field}.presence_rate"] = len(values) / max(1, len(items))
        if all(isinstance(value, bool) for value in values):
            output[f"{field}.true_rate"] = sum(1 for value in values if value) / max(1, len(values))
            continue
        numeric = [_to_float(value) for value in values if _is_number(value)]
        if numeric and len(numeric) == len(values):
            output[f"{field}.min"] = min(numeric)
            output[f"{field}.max"] = max(numeric)
            output[f"{field}.mean"] = sum(numeric) / max(1, len(numeric))
            output[f"{field}.sum"] = sum(numeric)
            output[f"{field}.range"] = max(numeric) - min(numeric)
            output[f"{field}.nonzero_rate"] = sum(1 for value in numeric if abs(value) > 1e-9) / max(1, len(numeric))
            continue
        categories = [_category(value) for value in values if isinstance(value, (str, bool))]
        if categories:
            counts: dict[str, int] = {}
            for category in categories:
                token = _safe_token(category)
                counts[token] = counts.get(token, 0) + 1
            output[f"{field}.distinct_count"] = len(counts)
            for token, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:8]:
                output[f"{field}.category.{token}.rate"] = count / max(1, len(categories))
    return output


def _scalar_list_summaries(values: list[Any], *, base: str) -> dict[str, Any]:
    output: dict[str, Any] = {}
    if all(isinstance(value, bool) for value in values):
        output[f"{base}.true_rate"] = sum(1 for value in values if value) / max(1, len(values))
        return output
    numeric = [_to_float(value) for value in values if _is_number(value)]
    if numeric and len(numeric) == len(values):
        output[f"{base}.min"] = min(numeric)
        output[f"{base}.max"] = max(numeric)
        output[f"{base}.mean"] = sum(numeric) / max(1, len(numeric))
        output[f"{base}.sum"] = sum(numeric)
        output[f"{base}.range"] = max(numeric) - min(numeric)
        return output
    counts: dict[str, int] = {}
    for value in values:
        token = _safe_token(_category(value))
        counts[token] = counts.get(token, 0) + 1
    output[f"{base}.distinct_count"] = len(counts)
    for token, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:8]:
        output[f"{base}.category.{token}.rate"] = count / max(1, len(values))
    return output


def _relation_fields(flat: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    output.update(_expected_observed_relations(flat))
    output.update(_same_leaf_relations(flat))
    return output


def _complex_relation_fields(value: Any, *, prefix: str = "") -> dict[str, Any]:
    output: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            output.update(_complex_relation_fields(item, prefix=child))
        return output
    if not isinstance(value, (list, tuple, set)):
        return output
    dict_items = [item for item in value if isinstance(item, dict)]
    if not dict_items:
        return output
    deltas: list[float] = []
    consistency_errors: list[float] = []
    matches = 0
    for item in dict_items:
        flat_item = _flatten(item)
        expected = flat_item.get("expected")
        observed = flat_item.get("observed", flat_item.get("actual"))
        if not (_is_number(expected) and _is_number(observed)):
            continue
        delta = _to_float(observed) - _to_float(expected)
        deltas.append(delta)
        matches += int(abs(delta) <= 1e-9)
        if _is_number(flat_item.get("delta")):
            consistency_errors.append(abs(_to_float(flat_item.get("delta")) - delta))
    if deltas:
        base = f"relations.{prefix}" if prefix else "relations.root_list"
        output[f"{base}.expected_observed_abs_delta"] = max(abs(item) for item in deltas)
        output[f"{base}.expected_observed_mean_abs_delta"] = sum(abs(item) for item in deltas) / max(1, len(deltas))
        output[f"{base}.expected_observed_match_rate"] = matches / max(1, len(deltas))
        if consistency_errors:
            output[f"{base}.delta_consistency_error"] = max(consistency_errors)
    return output


def _expected_observed_relations(flat: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    grouped: dict[str, dict[str, Any]] = {}
    for path, value in flat.items():
        if not is_trainable_world_field(path, value):
            continue
        parent, leaf = path.rsplit(".", 1) if "." in path else ("", path)
        if leaf in {"expected", "observed", "actual", "delta"}:
            grouped.setdefault(parent, {})[leaf] = value
    for parent, values in grouped.items():
        expected = values.get("expected")
        observed = values.get("observed", values.get("actual"))
        if not (_is_number(expected) and _is_number(observed)):
            continue
        delta = _to_float(observed) - _to_float(expected)
        base = f"relations.{parent}" if parent else "relations.root"
        output[f"{base}.observed_minus_expected"] = delta
        output[f"{base}.observed_expected_abs_delta"] = abs(delta)
        output[f"{base}.observed_expected_match"] = abs(delta) <= 1e-9
        if _is_number(values.get("delta")):
            output[f"{base}.delta_consistency_error"] = abs(_to_float(values.get("delta")) - delta)
    return output


def _same_leaf_relations(flat: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    grouped: dict[str, list[tuple[str, Any]]] = {}
    for path, value in flat.items():
        if not is_trainable_world_field(path, value):
            continue
        leaf = path.rsplit(".", 1)[-1]
        if leaf in {"count", "min", "max", "mean", "sum", "range"}:
            continue
        grouped.setdefault(leaf, []).append((path, value))
    for leaf, items in grouped.items():
        if len(items) < 2:
            continue
        base = f"relations.same_leaf.{_safe_token(leaf)}"
        numeric = [_to_float(value) for _, value in items if _is_number(value)]
        if numeric and len(numeric) == len(items):
            output[f"{base}.count"] = len(numeric)
            output[f"{base}.range"] = max(numeric) - min(numeric)
            output[f"{base}.all_equal"] = (max(numeric) - min(numeric)) <= 1e-9
            continue
        categories = [_category(value) for _, value in items if isinstance(value, (str, bool))]
        if categories and len(categories) == len(items):
            output[f"{base}.count"] = len(categories)
            output[f"{base}.distinct_count"] = len(set(categories))
            output[f"{base}.all_equal"] = len(set(categories)) <= 1
    return output


def _category(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value if value is not None else MISSING_TOKEN)


def _is_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError):
        return False


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _safe_token(value: Any) -> str:
    text = str(value if value is not None else MISSING_TOKEN).strip().lower()
    text = re.sub(r"[^a-z0-9_.:-]+", "_", text)
    return (text.strip("._-") or "empty")[:48]


def _relation_mentions_target(path: str, field_path: str, leaf: str, parent: str) -> bool:
    if field_path and field_path in path:
        return True
    if parent and parent in path:
        return True
    return bool(leaf and f".{_safe_token(leaf)}." in path)


def _summary_mentions_target(path: str, field_path: str, leaf: str, parent: str) -> bool:
    if field_path and field_path in path:
        return True
    if parent and path.startswith(f"summary.{parent}."):
        return True
    return bool(leaf and f".{leaf}." in path)


def _related_leaf(candidate: str, target: str) -> bool:
    common = {
        "expected": {"observed", "delta", "actual"},
        "observed": {"expected", "delta", "actual"},
        "actual": {"expected", "observed", "delta"},
        "delta": {"expected", "observed", "actual"},
    }
    return candidate in common.get(target, set())
