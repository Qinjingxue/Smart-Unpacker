from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.features import damage_labels_for_row
from repair_training.core.normal_structure_inference import NormalStructureModel
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name
from sunpack.repair.policy.adapters.normal_structure import get_normal_structure_adapter


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    adapter = get_normal_structure_adapter(fmt)
    if adapter is None:
        raise SystemExit(f"no normal structure adapter for format: {fmt}")
    model = NormalStructureModel(model_dir=args.normal_model_dir, plugin=plugin)
    rows = read_jsonl(args.input)
    predictions: list[dict[str, Any]] = []
    totals = _MetricTotals()
    per_profile: dict[str, _MetricTotals] = defaultdict(_MetricTotals)
    per_field: dict[str, Counter] = defaultdict(Counter)

    for index, row in enumerate(rows):
        payload = row.get("damage_analysis_input") if isinstance(row.get("damage_analysis_input"), dict) else {}
        query_rows = adapter.rows_from_request_payload(payload)
        scores = model.predict_rows(query_rows)
        anomaly = adapter.build_anomaly_payload(query_rows, scores)
        truth = _truth_from_row(row)
        ranked_fields = _ranked_fields(anomaly)
        ranked_zones = _ranked_zones(anomaly)
        ranked_relations = _ranked_relations(anomaly)
        ranked_pairs = _ranked_conflict_pairs(anomaly)
        expected_relations = sorted({_expected_relation_for_field(field) for field in truth["fields"] if _expected_relation_for_field(field)})
        expected_pairs = sorted({_expected_pair_for_field(field) for field in truth["fields"] if _expected_pair_for_field(field)})
        record = {
            "row_index": index,
            "sample_id": row.get("sample_id") or row.get("episode_id") or row.get("source_identity", {}).get("sample_id"),
            "profile": _profile(row),
            "true_fields": truth["fields"],
            "true_zones": truth["zones"],
            "expected_relations": expected_relations,
            "expected_conflict_pairs": expected_pairs,
            "top_fields": ranked_fields[: args.top_k],
            "top_fields5": ranked_fields[:5],
            "top_zones": ranked_zones[: args.top_k],
            "top_relations": ranked_relations[: args.top_k],
            "top_conflict_pairs": ranked_pairs[: args.top_k],
            "max_anomaly": float((anomaly.get("summary") or {}).get("max_anomaly") or 0.0),
        }
        predictions.append(record)
        totals.add(record)
        per_profile[record["profile"]].add(record)
        for field in truth["fields"]:
            per_field[field].update(_field_hits(field, ranked_fields, args.top_k))

    metrics = totals.to_dict(top_k=args.top_k)
    metrics["format"] = fmt
    metrics["rows"] = len(rows)
    metrics["input"] = str(args.input)
    metrics["normal_model_dir"] = str(args.normal_model_dir)
    metrics["per_profile"] = {key: value.to_dict(top_k=args.top_k) for key, value in sorted(per_profile.items())}
    metrics["per_field"] = {
        key: _counter_rates(counter)
        for key, counter in sorted(per_field.items())
    }
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "normal_structure_attribution_metrics.json", metrics)
    write_jsonl(output / "normal_structure_attribution_predictions.jsonl", predictions)
    hard_cases = [
        item for item in predictions
        if item["true_fields"] and not _topk_contains(item["top_fields"], set(item["true_fields"]), args.top_k)
    ]
    write_jsonl(output / "normal_structure_attribution_hard_cases.jsonl", hard_cases)
    print(json.dumps(metrics, ensure_ascii=False, sort_keys=True))
    return 0


class _MetricTotals:
    def __init__(self) -> None:
        self.rows = 0
        self.field_rows = 0
        self.zone_rows = 0
        self.relation_rows = 0
        self.conflict_pair_rows = 0
        self.field_top1_hits = 0
        self.field_topk_hits = 0
        self.field_top5_recall_sum = 0.0
        self.zone_top1_hits = 0
        self.zone_topk_hits = 0
        self.relation_topk_hits = 0
        self.conflict_pair_topk_hits = 0
        self.field_recall_sum = 0.0
        self.zone_recall_sum = 0.0

    def add(self, record: dict[str, Any]) -> None:
        self.rows += 1
        fields = set(record.get("true_fields") or [])
        zones = set(record.get("true_zones") or [])
        relations = set(record.get("expected_relations") or [])
        conflict_pairs = set(record.get("expected_conflict_pairs") or [])
        top_fields = [item["field"] for item in record.get("top_fields") or []]
        top_fields5 = [item["field"] for item in record.get("top_fields5") or []]
        top_zones = [item["zone"] for item in record.get("top_zones") or []]
        top_relations = [item["relation_kind"] for item in record.get("top_relations") or []]
        top_conflict_pairs = [item["conflict_pair"] for item in record.get("top_conflict_pairs") or []]
        if fields:
            self.field_rows += 1
            self.field_top1_hits += int(bool(top_fields and top_fields[0] in fields))
            self.field_topk_hits += int(bool(fields.intersection(top_fields)))
            self.field_recall_sum += len(fields.intersection(top_fields)) / max(1, len(fields))
            self.field_top5_recall_sum += len(fields.intersection(top_fields5)) / max(1, len(fields))
        if zones:
            self.zone_rows += 1
            self.zone_top1_hits += int(bool(top_zones and top_zones[0] in zones))
            self.zone_topk_hits += int(bool(zones.intersection(top_zones)))
            self.zone_recall_sum += len(zones.intersection(top_zones)) / max(1, len(zones))
        if relations:
            self.relation_rows += 1
            self.relation_topk_hits += int(bool(relations.intersection(top_relations)))
        if conflict_pairs:
            self.conflict_pair_rows += 1
            self.conflict_pair_topk_hits += int(bool(conflict_pairs.intersection(top_conflict_pairs)))

    def to_dict(self, *, top_k: int) -> dict[str, Any]:
        return {
            "rows": self.rows,
            "field_rows": self.field_rows,
            "zone_rows": self.zone_rows,
            "relation_rows": self.relation_rows,
            "field_top1_accuracy": _rate(self.field_top1_hits, self.field_rows),
            f"field_top{top_k}_hit_rate": _rate(self.field_topk_hits, self.field_rows),
            f"field_top{top_k}_recall": self.field_recall_sum / self.field_rows if self.field_rows else 0.0,
            "field_top5_recall": self.field_top5_recall_sum / self.field_rows if self.field_rows else 0.0,
            "zone_top1_accuracy": _rate(self.zone_top1_hits, self.zone_rows),
            f"zone_top{top_k}_hit_rate": _rate(self.zone_topk_hits, self.zone_rows),
            f"zone_top{top_k}_recall": self.zone_recall_sum / self.zone_rows if self.zone_rows else 0.0,
            f"relation_kind_top{top_k}_recall": _rate(self.relation_topk_hits, self.relation_rows),
            f"conflict_pair_top{top_k}_hit_rate": _rate(self.conflict_pair_topk_hits, self.conflict_pair_rows),
        }


def _truth_from_row(row: dict[str, Any]) -> dict[str, list[str]]:
    labels = damage_labels_for_row(row)
    fields = sorted(label.split(":", 1)[1] for label in labels if label.startswith("field:"))
    zones = sorted(label.split(":", 1)[1] for label in labels if label.startswith("zone:"))
    for field in fields:
        zone = _zone_for_field(field)
        if zone and zone not in zones:
            zones.append(zone)
    return {"fields": fields, "zones": sorted(set(zones))}


def _ranked_fields(anomaly: dict[str, Any]) -> list[dict[str, Any]]:
    compact = _compact(anomaly)
    by_field = compact.get("by_field") if isinstance(compact.get("by_field"), dict) else {}
    if by_field:
        return [
            {"field": str(field), "anomaly": float((payload or {}).get("max") or 0.0)}
            for field, payload in sorted(by_field.items(), key=lambda item: float((item[1] or {}).get("max") or 0.0), reverse=True)
            if isinstance(payload, dict)
        ]
    summary = anomaly.get("summary") if isinstance(anomaly.get("summary"), dict) else {}
    fields = summary.get("max_anomaly_by_field") if isinstance(summary.get("max_anomaly_by_field"), dict) else {}
    return [
        {"field": str(field), "anomaly": float(score or 0.0)}
        for field, score in sorted(fields.items(), key=lambda item: float(item[1] or 0.0), reverse=True)
    ]


def _ranked_zones(anomaly: dict[str, Any]) -> list[dict[str, Any]]:
    compact = _compact(anomaly)
    by_field = compact.get("by_field") if isinstance(compact.get("by_field"), dict) else {}
    if by_field:
        scores: dict[str, list[float]] = defaultdict(list)
        for field, payload in by_field.items():
            if isinstance(payload, dict):
                scores[_zone_for_field(str(field))].append(float(payload.get("max") or 0.0))
        return [
            {"zone": zone, "anomaly": max(values)}
            for zone, values in sorted(scores.items(), key=lambda item: max(item[1]), reverse=True)
        ]
    summary = anomaly.get("summary") if isinstance(anomaly.get("summary"), dict) else {}
    zones = summary.get("mean_anomaly_by_zone") if isinstance(summary.get("mean_anomaly_by_zone"), dict) else {}
    return [
        {"zone": str(zone), "anomaly": float(score or 0.0)}
        for zone, score in sorted(zones.items(), key=lambda item: float(item[1] or 0.0), reverse=True)
    ]


def _ranked_relations(anomaly: dict[str, Any]) -> list[dict[str, Any]]:
    compact = _compact(anomaly)
    by_relation = compact.get("by_relation") if isinstance(compact.get("by_relation"), dict) else {}
    if by_relation:
        return [
            {"relation_kind": str(relation), "anomaly": float((payload or {}).get("max") or 0.0)}
            for relation, payload in sorted(by_relation.items(), key=lambda item: float((item[1] or {}).get("max") or 0.0), reverse=True)
            if isinstance(payload, dict)
        ]
    scores: dict[str, float] = {}
    for query in anomaly.get("queries") or []:
        if not isinstance(query, dict):
            continue
        relation = str(query.get("relation_kind") or query.get("query_type") or "")
        if not relation:
            continue
        scores[relation] = max(scores.get(relation, 0.0), float(query.get("anomaly_score") or 0.0))
    return [
        {"relation_kind": str(relation), "anomaly": float(score)}
        for relation, score in sorted(scores.items(), key=lambda item: item[1], reverse=True)
    ]


def _ranked_conflict_pairs(anomaly: dict[str, Any]) -> list[dict[str, Any]]:
    pairs = _compact(anomaly).get("conflict_pairs")
    if not isinstance(pairs, dict):
        return []
    return [
        {"conflict_pair": str(name), "anomaly": float((payload or {}).get("score") or 0.0)}
        for name, payload in sorted(pairs.items(), key=lambda item: float((item[1] or {}).get("score") or 0.0), reverse=True)
        if isinstance(payload, dict)
    ]


def _compact(anomaly: dict[str, Any]) -> dict[str, Any]:
    compact = anomaly.get("compact_attribution") if isinstance(anomaly.get("compact_attribution"), dict) else {}
    return compact


def _expected_relation_for_field(field: str) -> str:
    text = str(field or "")
    if any(part in text for part in ("offset", "zip64.locator")):
        return "points_to"
    if any(part in text for part in ("compressed_size", "uncompressed_size", "payload", "record", "tail", "missing_range")):
        return "owns_span"
    if any(part in text for part in ("crc", "flags", "method", "filename", "header")):
        return "should_match"
    if text.startswith("eocd."):
        return "field_value"
    return "field_value"


def _expected_pair_for_field(field: str) -> str:
    text = str(field or "")
    mapping = {
        "eocd.cd_offset": "eocd_cd_offset",
        "eocd.cd_size": "eocd_cd_size",
        "eocd.entry_count": "eocd_entry_count",
        "central_directory.local_header_offset": "cd_local_offset",
        "central_directory.crc": "cd_local_crc",
        "local_header.crc": "cd_local_crc",
        "central_directory.flags": "cd_local_flags",
        "local_header.flags": "cd_local_flags",
        "central_directory.filename": "cd_local_name",
        "central_directory.compressed_size": "cd_compressed_size_span",
        "local_header.compressed_size": "cd_compressed_size_span",
        "payload.compressed_data": "missing_range_payload_span",
        "data_descriptor.record": "payload_descriptor_span",
        "sfx_prefix.bytes": "sfx_cd_offset",
        "split_volume.missing_range": "missing_range_payload_span",
        "zip64.extra_length": "zip64_extra_override",
        "zip64.uncompressed_size": "zip64_extra_override",
    }
    return mapping.get(text, "")


def _field_hits(field: str, ranked_fields: list[dict[str, Any]], top_k: int) -> Counter:
    names = [item["field"] for item in ranked_fields]
    return Counter({
        "count": 1,
        "top1": int(bool(names and names[0] == field)),
        "topk": int(field in names[:top_k]),
    })


def _counter_rates(counter: Counter) -> dict[str, Any]:
    total = int(counter.get("count", 0))
    return {
        "count": total,
        "top1_accuracy": _rate(counter.get("top1", 0), total),
        "topk_hit_rate": _rate(counter.get("topk", 0), total),
    }


def _topk_contains(items: list[dict[str, Any]], expected: set[str], top_k: int) -> bool:
    key = "field" if items and "field" in items[0] else "zone"
    return bool(expected.intersection(str(item.get(key) or "") for item in items[:top_k]))


def _zone_for_field(field: str) -> str:
    text = str(field or "")
    if "." not in text:
        return text
    head = text.split(".", 1)[0]
    if head == "data_descriptor":
        return "data_descriptor"
    if head in {"central_directory", "local_header", "split_volume", "sfx_prefix", "zip64"}:
        return head
    return head


def _profile(row: dict[str, Any]) -> str:
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    return str(metadata.get("damage_profile") or metadata.get("profile") or metadata.get("eval_profile") or "unknown")


def _rate(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate NormalStructureModel field attribution against damage labels.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True, help="damage_rows.jsonl or raw damage rows with damage_analysis_input/target")
    parser.add_argument("--normal-model-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--top-k", type=int, default=3)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
