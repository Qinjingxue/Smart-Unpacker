from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from repair_training.core.datasets import write_json, write_jsonl
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples
from repair_training.core.diagnosis_gnn.inference import DiagnosisGNNModel
from repair_training.core.diagnosis_gnn.metrics import binary_multilabel_metrics, clean_false_positive_rate
from repair_training.core.diagnosis_gnn.tensorize import metadata_for_sample
from repair_training.core.diagnosis_gnn.training import train_diagnosis_gnn_model
from repair_training.core.plugin import normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    samples = read_diagnosis_graph_samples(args.input)
    profiles = _selected_profiles(samples, profiles_arg=args.profiles, min_count=int(args.min_count), max_profiles=int(args.max_profiles))
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    per_profile = []
    for profile in profiles:
        profile_dir = output / _safe_name(profile)
        datasets_dir = profile_dir / "datasets"
        model_dir = profile_dir / "model"
        eval_dir = profile_dir / "eval"
        datasets_dir.mkdir(parents=True, exist_ok=True)
        eval_dir.mkdir(parents=True, exist_ok=True)
        train_samples = [sample for sample in samples if _sample_profile(sample) not in {profile}]
        test_samples = [sample for sample in samples if _sample_profile(sample) == profile and not _is_synthetic(sample)]
        train_path = datasets_dir / "train.jsonl"
        test_path = datasets_dir / "test.jsonl"
        write_jsonl(train_path, [sample.to_dict() for sample in train_samples])
        write_jsonl(test_path, [sample.to_dict() for sample in test_samples])
        train_metrics = train_diagnosis_gnn_model(
            input_path=train_path,
            model_dir=model_dir,
            run_id=f"heldout_{_safe_name(profile)}",
            format_name=fmt,
            config={
                "epochs": int(args.epochs),
                "batch_size": int(args.batch_size),
                "hidden_dim": int(args.hidden_dim),
                "layers": int(args.layers),
                "early_stopping_patience": int(args.early_stopping_patience),
            },
            device=args.device,
        )
        model = DiagnosisGNNModel(model_dir=model_dir, device=args.device)
        predictions, metrics = _evaluate_samples(model, test_samples)
        metrics["profile"] = profile
        metrics["train_rows"] = len(train_samples)
        metrics["test_rows"] = len(test_samples)
        metrics["train_best_valid_loss"] = train_metrics.get("best_valid_loss")
        write_jsonl(eval_dir / "predictions.jsonl", predictions)
        write_json(eval_dir / "metrics.json", metrics)
        per_profile.append(metrics)
    summary = {
        "format": fmt,
        "input": str(args.input),
        "profiles": profiles,
        "profile_count": len(profiles),
        "macro": _macro_summary(per_profile),
        "profiles_metrics": per_profile,
    }
    write_json(output / "heldout_profile_summary.json", summary)
    print(json.dumps({"output": str(output), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def _selected_profiles(samples, *, profiles_arg: str, min_count: int, max_profiles: int) -> list[str]:
    counts = Counter(_sample_profile(sample) for sample in samples if _sample_profile(sample) and not _is_synthetic(sample))
    if profiles_arg:
        return [item.strip() for item in profiles_arg.split(",") if item.strip()]
    profiles = [profile for profile, count in counts.items() if count >= min_count]
    profiles.sort(key=lambda item: (-counts[item], item))
    if max_profiles > 0:
        profiles = profiles[:max_profiles]
    return profiles


def _sample_profile(sample) -> str:
    aux = sample.labels.auxiliary if isinstance(sample.labels.auxiliary, dict) else {}
    return str(aux.get("damage_profile") or "")


def _is_synthetic(sample) -> bool:
    aux = sample.labels.auxiliary if isinstance(sample.labels.auxiliary, dict) else {}
    return bool(aux.get("synthetic"))


def _evaluate_samples(model: DiagnosisGNNModel, samples) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    predictions = []
    cause_score_rows = []
    cause_label_rows = []
    field_scores = []
    field_labels = []
    zone_scores = []
    zone_labels = []
    thresholds = _thresholds_for_model(model)
    for sample in samples:
        pred = model.predict_sample(sample)
        metadata = metadata_for_sample(sample)
        scores_by_node = dict((pred.get("root_cause") or {}).get("cause_scores") or {})
        cause_score_rows.append([float(scores_by_node.get(node_id, 0.0)) for node_id in metadata.cause_node_ids])
        label_set = set(sample.labels.cause_node_ids)
        cause_label_rows.append([1.0 if node_id in label_set else 0.0 for node_id in metadata.cause_node_ids])
        root = pred.get("root_cause") if isinstance(pred.get("root_cause"), dict) else {}
        field_scores.append(dict(root.get("field_scores") or {}))
        field_labels.append(list(sample.labels.field_labels))
        zone_scores.append(dict(root.get("zone_scores") or {}))
        zone_labels.append([label.split(":", 1)[1] for label in sample.labels.zone_labels if ":" in label])
        predictions.append({
            "sample_id": sample.sample_id,
            "true_field_labels": list(sample.labels.field_labels),
            "true_zone_labels": list(sample.labels.zone_labels),
            **pred,
        })
    metrics = {
        "thresholds": thresholds,
        "cause": binary_multilabel_metrics(cause_score_rows, cause_label_rows, threshold=thresholds["cause_threshold"]),
        "clean_false_positive_rate": clean_false_positive_rate(cause_score_rows, cause_label_rows, threshold=thresholds["cause_threshold"]),
        "field": _label_score_metrics(field_scores, field_labels, threshold=thresholds["field_threshold"]),
        "zone": _label_score_metrics(zone_scores, zone_labels, threshold=thresholds["zone_threshold"]),
    }
    return predictions, metrics


def _thresholds_for_model(model: DiagnosisGNNModel) -> dict[str, float]:
    raw = model.thresholds if isinstance(model.thresholds, dict) else {}
    cause = raw.get("cause") if isinstance(raw.get("cause"), dict) else {}
    return {
        "cause_threshold": float(cause.get("threshold", raw.get("default_threshold", 0.5))),
        "field_threshold": float(raw.get("field_threshold", cause.get("threshold", 0.5))),
        "zone_threshold": float(raw.get("zone_threshold", cause.get("threshold", 0.5))),
    }


def _label_score_metrics(score_rows: list[dict[str, float]], label_rows: list[list[str]], *, threshold: float) -> dict[str, Any]:
    labels = sorted({label for row in label_rows for label in row} | {label for scores in score_rows for label in scores})
    if not labels:
        return {"micro_f1": 0.0, "top1_hit": 0.0, "top3_hit": 0.0, "top5_hit": 0.0, "threshold": threshold}
    score_matrix = [[float(scores.get(label, 0.0)) for label in labels] for scores in score_rows]
    label_matrix = [[1.0 if label in set(row) else 0.0 for label in labels] for row in label_rows]
    base = binary_multilabel_metrics(score_matrix, label_matrix, threshold=threshold)
    return {
        "threshold": threshold,
        "micro_f1": base["micro_f1"],
        "top1_hit": base["top1_hit"],
        "top3_hit": base["top3_hit"],
        "top5_hit": base["top5_hit"],
    }


def _macro_summary(rows: list[dict[str, Any]]) -> dict[str, float]:
    if not rows:
        return {}
    keys = (
        ("cause_top1_hit", "cause", "top1_hit"),
        ("cause_top3_hit", "cause", "top3_hit"),
        ("cause_top5_hit", "cause", "top5_hit"),
        ("cause_micro_f1", "cause", "micro_f1"),
        ("field_top1_hit", "field", "top1_hit"),
        ("field_top3_hit", "field", "top3_hit"),
        ("field_top5_hit", "field", "top5_hit"),
        ("zone_top1_hit", "zone", "top1_hit"),
        ("zone_top3_hit", "zone", "top3_hit"),
        ("zone_top5_hit", "zone", "top5_hit"),
    )
    output = {}
    for name, group, key in keys:
        output[name] = sum(float(((row.get(group) or {}).get(key) or 0.0)) for row in rows) / len(rows)
    return output


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value or "profile"))[:120] or "profile"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run heldout-profile DiagnosisGNN evaluation.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--profiles", default="")
    parser.add_argument("--min-count", type=int, default=8)
    parser.add_argument("--max-profiles", type=int, default=0)
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--layers", type=int, default=2)
    parser.add_argument("--early-stopping-patience", type=int, default=6)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
