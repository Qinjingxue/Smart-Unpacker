from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from repair_training.core.datasets import write_json, write_jsonl
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples
from sunpack.model_runtime.diagnosis.inference import DiagnosisGNNModel
from repair_training.core.diagnosis_gnn.metrics import binary_multilabel_metrics, clean_false_positive_rate
from sunpack.model_runtime.diagnosis.root_cases import ROOT_CASES
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
    root_score_rows = []
    root_label_rows = []
    thresholds = _thresholds_for_model(model)
    for sample in samples:
        pred = model.predict_sample(sample)
        root = pred.get("root_case") if isinstance(pred.get("root_case"), dict) else {}
        scores = root.get("scores") if isinstance(root.get("scores"), dict) else {}
        truth = set(sample.labels.root_case_labels)
        root_score_rows.append([float(scores.get(label, 0.0)) for label in ROOT_CASES])
        root_label_rows.append([1.0 if label in truth else 0.0 for label in ROOT_CASES])
        predictions.append({
            "sample_id": sample.sample_id,
            "true_root_case_labels": list(sample.labels.root_case_labels),
            **pred,
        })
    metrics = {
        "thresholds": thresholds,
        "root_case": binary_multilabel_metrics(root_score_rows, root_label_rows, threshold=thresholds["root_threshold"]),
        "clean_false_positive_rate": clean_false_positive_rate(root_score_rows, root_label_rows, threshold=thresholds["root_threshold"]),
    }
    return predictions, metrics


def _thresholds_for_model(model: DiagnosisGNNModel) -> dict[str, float]:
    raw = model.thresholds if isinstance(model.thresholds, dict) else {}
    cause = raw.get("cause") if isinstance(raw.get("cause"), dict) else {}
    return {
        "root_threshold": float(cause.get("threshold", raw.get("default_threshold", 0.5))),
    }


def _macro_summary(rows: list[dict[str, Any]]) -> dict[str, float]:
    if not rows:
        return {}
    keys = (
        ("root_top1_hit", "root_case", "top1_hit"),
        ("root_top3_hit", "root_case", "top3_hit"),
        ("root_top5_hit", "root_case", "top5_hit"),
        ("root_micro_f1", "root_case", "micro_f1"),
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
