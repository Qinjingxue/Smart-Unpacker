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


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    model = NormalStructureModel(model_dir=args.normal_model_dir, plugin=plugin)
    rows = read_jsonl(args.input)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    predictions: list[dict[str, Any]] = []
    totals = _Totals(top_k=int(args.top_k))
    per_profile: dict[str, _Totals] = defaultdict(lambda: _Totals(top_k=int(args.top_k)))
    zone_field_counts: dict[str, Counter] = defaultdict(Counter)

    worlds = model.analyze_knowledge_batch([
        row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else {}
        for row in rows
    ])
    for index, (row, world) in enumerate(zip(rows, worlds)):
        truth = _truth(row)
        top_fields = _top_fields(world, limit=max(1, int(args.top_k)))
        ranked_zones = _rank_zones(world)
        record = {
            "row_index": index,
            "sample_id": row.get("sample_id") or row.get("episode_id") or "",
            "profile": _profile(row),
            "true_labels": truth["labels"],
            "true_zones": truth["zones"],
            "true_fields": truth["fields"],
            "top_fields": top_fields,
            "top_zones": ranked_zones[: int(args.top_k)],
            "expected_zone_ranks": {
                zone: _rank_of_zone(zone, ranked_zones)
                for zone in truth["zones"]
            },
            "max_anomaly": float(((world.get("world_summary") or {}).get("max_anomaly")) or 0.0),
            "mean_topk_anomaly": float(((world.get("world_summary") or {}).get("mean_topk_anomaly")) or 0.0),
        }
        predictions.append(record)
        totals.add(record)
        per_profile[record["profile"]].add(record)
        for zone in truth["zones"]:
            for item in top_fields:
                if zone == _zone_for_world_field(str(item.get("field_path") or "")):
                    zone_field_counts[zone][str(item.get("field_path") or "")] += 1

    metrics = totals.to_dict()
    metrics.update({
        "format": fmt,
        "rows": len(rows),
        "input": str(args.input),
        "normal_model_dir": str(args.normal_model_dir),
        "top_k": int(args.top_k),
        "per_profile": {key: value.to_dict() for key, value in sorted(per_profile.items())},
        "top_hit_fields_by_zone": {
            zone: [{"field_path": field, "count": count} for field, count in counter.most_common(20)]
            for zone, counter in sorted(zone_field_counts.items())
        },
    })
    write_json(output / "world_damage_correlation_metrics.json", metrics)
    write_jsonl(output / "world_damage_correlation_predictions.jsonl", predictions)
    hard = [
        item for item in predictions
        if item.get("true_zones") and not set(item["true_zones"]).intersection(
            str(zone.get("zone") or "") for zone in item.get("top_zones") or []
        )
    ]
    write_jsonl(output / "world_damage_correlation_hard_cases.jsonl", hard)
    print(json.dumps(metrics, ensure_ascii=False, sort_keys=True))
    return 0


class _Totals:
    def __init__(self, *, top_k: int) -> None:
        self.top_k = int(top_k)
        self.rows = 0
        self.labeled_rows = 0
        self.zone_top1 = 0
        self.zone_topk = 0
        self.zone_recall_sum = 0.0
        self.zone_mrr_sum = 0.0
        self.field_token_topk = 0
        self.max_anomaly_sum = 0.0

    def add(self, record: dict[str, Any]) -> None:
        self.rows += 1
        self.max_anomaly_sum += float(record.get("max_anomaly") or 0.0)
        true_zones = set(record.get("true_zones") or [])
        true_fields = set(record.get("true_fields") or [])
        if not true_zones and not true_fields:
            return
        self.labeled_rows += 1
        top_zones = [str(item.get("zone") or "") for item in record.get("top_zones") or []]
        top_fields = [str(item.get("field_path") or "") for item in record.get("top_fields") or []]
        if true_zones:
            self.zone_top1 += int(bool(top_zones and top_zones[0] in true_zones))
            self.zone_topk += int(bool(true_zones.intersection(top_zones[: self.top_k])))
            self.zone_recall_sum += len(true_zones.intersection(top_zones[: self.top_k])) / max(1, len(true_zones))
            ranks = [int((record.get("expected_zone_ranks") or {}).get(zone) or 0) for zone in true_zones]
            best_rank = min([rank for rank in ranks if rank > 0] or [0])
            self.zone_mrr_sum += (1.0 / best_rank) if best_rank else 0.0
        if true_fields:
            self.field_token_topk += int(any(_field_label_matches_world_path(field, path) for field in true_fields for path in top_fields[: self.top_k]))

    def to_dict(self) -> dict[str, Any]:
        return {
            "rows": self.rows,
            "labeled_rows": self.labeled_rows,
            "zone_top1_accuracy": _rate(self.zone_top1, self.labeled_rows),
            f"zone_top{self.top_k}_hit_rate": _rate(self.zone_topk, self.labeled_rows),
            f"zone_top{self.top_k}_recall": self.zone_recall_sum / self.labeled_rows if self.labeled_rows else 0.0,
            "zone_mrr": self.zone_mrr_sum / self.labeled_rows if self.labeled_rows else 0.0,
            f"field_token_top{self.top_k}_hit_rate": _rate(self.field_token_topk, self.labeled_rows),
            "mean_max_anomaly": self.max_anomaly_sum / self.rows if self.rows else 0.0,
        }


def _truth(row: dict[str, Any]) -> dict[str, list[str]]:
    labels = sorted(set(damage_labels_for_row(row)))
    fields = sorted(label.split(":", 1)[1] for label in labels if label.startswith("field:"))
    zones = {label.split(":", 1)[1] for label in labels if label.startswith("zone:")}
    for field in fields:
        zone = _zone_for_damage_field(field)
        if zone:
            zones.add(zone)
    return {
        "labels": labels,
        "fields": fields,
        "zones": sorted(zones),
    }


def _top_fields(world: dict[str, Any], *, limit: int) -> list[dict[str, Any]]:
    summary = world.get("world_summary") if isinstance(world.get("world_summary"), dict) else {}
    items = summary.get("top_fields") if isinstance(summary.get("top_fields"), list) else []
    output = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        field_path = str(item.get("field_path") or "")
        output.append({
            "field_path": field_path,
            "score": float(item.get("score") or 0.0),
            "zone": _zone_for_world_field(field_path),
        })
    return output


def _rank_zones(world: dict[str, Any]) -> list[dict[str, Any]]:
    scores = world.get("world_field_scores") if isinstance(world.get("world_field_scores"), dict) else {}
    zone_scores: dict[str, list[float]] = defaultdict(list)
    for field_path, score in scores.items():
        zone = _zone_for_world_field(str(field_path))
        if zone:
            zone_scores[zone].append(float(score or 0.0))
    ranked = []
    for zone, values in zone_scores.items():
        ranked.append({
            "zone": zone,
            "score": max(values),
            "mean_score": sum(values) / max(1, len(values)),
            "field_count": len(values),
        })
    return sorted(ranked, key=lambda item: (float(item["score"]), float(item["mean_score"])), reverse=True)


def _rank_of_zone(zone: str, ranked_zones: list[dict[str, Any]]) -> int:
    for index, item in enumerate(ranked_zones, start=1):
        if str(item.get("zone") or "") == zone:
            return index
    return 0


def _zone_for_damage_field(field: str) -> str:
    text = str(field or "").lower()
    if text.startswith("eocd."):
        return "eocd"
    if text.startswith("central_directory."):
        return "central_directory"
    if text.startswith("local_header."):
        return "local_header"
    if text.startswith("data_descriptor."):
        return "data_descriptor"
    if text.startswith("payload."):
        return "payload"
    if text.startswith("sfx_prefix."):
        return "sfx"
    if text.startswith("split_volume."):
        return "split"
    if text.startswith("zip64."):
        return "zip64"
    return text.split(".", 1)[0] if "." in text else text


def _zone_for_world_field(field_path: str) -> str:
    text = str(field_path or "").lower()
    if "zip64" in text:
        return "zip64"
    if "sfx" in text or "carrier_prefix" in text:
        return "sfx"
    if "split" in text or "volume" in text:
        return "split"
    if "descriptor" in text:
        return "data_descriptor"
    if "payload" in text or "compressed_data" in text:
        return "payload"
    if "local_header" in text:
        return "local_header"
    if "central_directory" in text or "cd_entry" in text:
        return "central_directory"
    if "eocd" in text:
        return "eocd"
    if "crc" in text:
        return "crc"
    if "filename" in text or "name" in text or "encoding" in text or "utf" in text:
        return "filename"
    if "password" in text or "encrypt" in text:
        return "encryption"
    if "tail" in text or "trailing" in text or "comment" in text:
        return "tail"
    return "archive_structure"


def _field_label_matches_world_path(field: str, field_path: str) -> bool:
    zone = _zone_for_damage_field(field)
    if zone and zone == _zone_for_world_field(field_path):
        return True
    tokens = [part for part in field.replace("_", ".").split(".") if part]
    text = field_path.lower()
    return any(token.lower() in text for token in tokens)


def _profile(row: dict[str, Any]) -> str:
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    return str(metadata.get("damage_profile") or metadata.get("profile") or metadata.get("eval_profile") or "unknown")


def _rate(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate World field anomaly scores against damaged ZIP labels.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True, help="damage_rows.jsonl with knowledge_payload and damage labels")
    parser.add_argument("--normal-model-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--top-k", type=int, default=10)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
