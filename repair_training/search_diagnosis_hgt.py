from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from repair_training.core.datasets import write_json
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples
from repair_training.core.diagnosis_gnn.inference import DiagnosisGNNModel
from repair_training.core.diagnosis_gnn.metrics import (
    binary_multilabel_metrics,
    clean_false_positive_rate,
    multilabel_set_metrics,
)
from repair_training.core.diagnosis_gnn.root_cases import ROOT_CASES
from repair_training.core.diagnosis_gnn.training import train_diagnosis_gnn_model


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    run_dir = Path(args.run_dir)
    output = Path(args.output or run_dir / "reports" / "hgt_search_summary.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    model_root = Path(args.model_root or run_dir / "models")
    cache_dir = Path(args.tensor_cache_dir or run_dir / "tmp" / "diagnosis_hgt_tensor_cache")
    stage1_configs = _stage1_grid(args)
    if args.max_stage1_configs:
        stage1_configs = stage1_configs[: max(1, int(args.max_stage1_configs))]
    summary: dict[str, Any] = {
        "input": str(args.input),
        "heldout": str(args.heldout or ""),
        "stage1": [],
        "stage2": [],
        "selection_metric": "valid set_exact_topN, then set_recall_topN, then root_case_micro_f1",
    }
    for index, config in enumerate(stage1_configs, start=1):
        name = _config_name("stage1", index, config)
        model_dir = model_root / name
        metrics = train_diagnosis_gnn_model(
            format_name=args.format,
            input_path=args.input,
            model_dir=model_dir,
            config={
                **config,
                "epochs": int(args.stage1_epochs),
                "early_stopping_patience": int(args.stage1_patience),
                "batch_size": int(args.batch_size),
                "tensor_cache_dir": str(cache_dir),
            },
            device=args.device,
        )
        item = {
            "name": name,
            "model_dir": str(model_dir),
            "config": config,
            "valid": metrics.get("valid", {}),
            "test": metrics.get("test", {}),
            "train_time": _train_time(metrics),
            "peak_cuda_memory_mb": metrics.get("peak_cuda_memory_mb", 0.0),
        }
        summary["stage1"].append(item)
        write_json(output, summary)
        print(json.dumps({"stage": 1, "index": index, "config": config, "valid": item["valid"]}, ensure_ascii=False, sort_keys=True))
    top = sorted(summary["stage1"], key=_selection_key, reverse=True)[: max(1, int(args.stage2_top_k))]
    for index, selected in enumerate(top, start=1):
        config = dict(selected["config"])
        name = _config_name("stage2", index, config)
        model_dir = model_root / name
        metrics = train_diagnosis_gnn_model(
            format_name=args.format,
            input_path=args.input,
            model_dir=model_dir,
            config={
                **config,
                "epochs": int(args.stage2_epochs),
                "early_stopping_patience": int(args.stage2_patience),
                "batch_size": int(args.batch_size),
                "tensor_cache_dir": str(cache_dir),
            },
            device=args.device,
        )
        heldout_metrics = _evaluate_model(model_dir=model_dir, input_path=args.heldout, device=args.device) if args.heldout else {}
        item = {
            "name": name,
            "model_dir": str(model_dir),
            "selected_from": selected["name"],
            "config": config,
            "valid": metrics.get("valid", {}),
            "test": metrics.get("test", {}),
            "heldout": heldout_metrics,
            "train_time": _train_time(metrics),
            "peak_cuda_memory_mb": metrics.get("peak_cuda_memory_mb", 0.0),
        }
        summary["stage2"].append(item)
        write_json(output, summary)
        print(json.dumps({"stage": 2, "index": index, "config": config, "valid": item["valid"], "heldout": heldout_metrics}, ensure_ascii=False, sort_keys=True))
    if summary["stage2"]:
        best = sorted(summary["stage2"], key=_stage2_key, reverse=True)[0]
        best_dir = model_root / "diagnosis_gnn_hgt_v2_best"
        if best_dir.exists():
            shutil.rmtree(best_dir)
        shutil.copytree(best["model_dir"], best_dir)
        summary["best"] = {**best, "recommended_model_dir": str(best_dir)}
    write_json(output, summary)
    print(json.dumps({"output": str(output), "best": summary.get("best", {})}, ensure_ascii=False, sort_keys=True))
    return 0


def _stage1_grid(args) -> list[dict[str, Any]]:
    arch_grid = [
        (96, 4, 2),
        (128, 4, 2),
        (128, 8, 2),
        (96, 4, 3),
        (192, 8, 2),
        (128, 8, 4),
        (192, 8, 3),
        (192, 8, 4),
        (256, 8, 2),
        (256, 8, 3),
        (256, 8, 4),
    ]
    dropouts = [0.15, 0.20, 0.25]
    losses = ["bce", "weighted_bce", "focal"]
    configs = []
    for dropout in dropouts:
        for loss in losses:
            for hidden_dim, heads, layers in arch_grid:
                configs.append({
                    "arch": "hgt",
                    "hidden_dim": hidden_dim,
                    "heads": heads,
                    "layers": layers,
                    "dropout": dropout,
                    "lr": 7e-4 if hidden_dim <= 128 else 5e-4,
                    "weight_decay": 1e-4,
                    "edge_loss_weight": 0.35,
                    "loss": loss,
                    "focal_gamma": 2.0,
                    "pos_weight_max": 8.0,
                    "sample_weighting": "multi_field_root_count",
                    "residual": True,
                    "layernorm": True,
                    "amp": bool(args.amp),
                })
    return configs


def _config_name(prefix: str, index: int, config: dict[str, Any]) -> str:
    return (
        f"diagnosis_gnn_hgt_v2_{prefix}_{index:02d}_"
        f"h{config['hidden_dim']}_heads{config['heads']}_l{config['layers']}_"
        f"d{str(config['dropout']).replace('.', '')}_{config['loss']}"
    )


def _selection_key(item: dict[str, Any]) -> tuple[float, float, float, float, float]:
    valid = item.get("valid") or {}
    return (
        float(valid.get("set_exact_topN", 0.0)),
        float(valid.get("set_recall_topN", 0.0)),
        float(valid.get("set_exact_top5", 0.0)),
        float(valid.get("root_case_micro_f1", 0.0)),
        -float(valid.get("clean_false_positive_rate", 1.0)),
    )


def _stage2_key(item: dict[str, Any]) -> tuple[float, float, float, float]:
    valid = item.get("valid") or {}
    return (
        float(valid.get("set_exact_topN", 0.0)),
        float(valid.get("set_recall_topN", 0.0)),
        float(valid.get("root_case_micro_f1", 0.0)),
        -float(valid.get("clean_false_positive_rate", 1.0)),
    )


def _train_time(metrics: dict[str, Any]) -> dict[str, float]:
    history = metrics.get("history") if isinstance(metrics.get("history"), list) else []
    seconds = sum(float(item.get("epoch_seconds", 0.0)) for item in history if isinstance(item, dict))
    samples_per_second = [
        float(item.get("samples_per_second", 0.0))
        for item in history
        if isinstance(item, dict) and float(item.get("samples_per_second", 0.0)) > 0
    ]
    return {
        "seconds": round(seconds, 3),
        "mean_samples_per_second": round(sum(samples_per_second) / max(1, len(samples_per_second)), 3),
    }


def _evaluate_model(*, model_dir: str | Path, input_path: str | Path, device: str) -> dict[str, Any]:
    samples = read_diagnosis_graph_samples(input_path)
    if not samples:
        return {"rows": 0}
    model = DiagnosisGNNModel(model_dir=model_dir, device=device)
    threshold = _root_threshold(model)
    score_rows = []
    label_rows = []
    for sample, pred in zip(samples, model.predict_samples(samples)):
        root = pred.get("root_case") if isinstance(pred.get("root_case"), dict) else {}
        scores = root.get("scores") if isinstance(root.get("scores"), dict) else {}
        label_set = set(sample.labels.root_case_labels)
        score_rows.append([float(scores.get(label, 0.0)) for label in ROOT_CASES])
        label_rows.append([1.0 if label in label_set else 0.0 for label in ROOT_CASES])
    set_metrics = multilabel_set_metrics(score_rows, label_rows)
    binary = binary_multilabel_metrics(score_rows, label_rows, threshold=threshold)
    return {
        "rows": len(samples),
        "root_case_threshold": threshold,
        "root_case_micro_f1": binary["micro_f1"],
        "root_case_micro_precision": binary["micro_precision"],
        "root_case_micro_recall": binary["micro_recall"],
        "root_case_top1_hit": binary["top1_hit"],
        "root_case_top3_hit": binary["top3_hit"],
        "root_case_top5_hit": binary["top5_hit"],
        "set_recall_top5": set_metrics["recall_top5"],
        "set_recall_topN": set_metrics["recall_topN"],
        "set_exact_top5": set_metrics["exact_top5"],
        "set_exact_topN": set_metrics["exact_topN"],
        "set_by_root_count": set_metrics["by_root_count"],
        "clean_false_positive_rate": clean_false_positive_rate(score_rows, label_rows, threshold=threshold),
    }


def _root_threshold(model: DiagnosisGNNModel) -> float:
    raw = model.thresholds if isinstance(model.thresholds, dict) else {}
    root = raw.get("root_case") if isinstance(raw.get("root_case"), dict) else {}
    return float(root.get("threshold", raw.get("root_case_threshold", raw.get("default_threshold", 0.5))))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Search DiagnosisGNN HGT v2 training conditions.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--heldout", default="")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--model-root", default="")
    parser.add_argument("--output", default="")
    parser.add_argument("--tensor-cache-dir", default="")
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    parser.add_argument("--batch-size", type=int, default=24)
    parser.add_argument("--stage1-epochs", type=int, default=20)
    parser.add_argument("--stage1-patience", type=int, default=5)
    parser.add_argument("--stage2-epochs", type=int, default=60)
    parser.add_argument("--stage2-patience", type=int, default=10)
    parser.add_argument("--stage2-top-k", type=int, default=3)
    parser.add_argument("--max-stage1-configs", type=int, default=0)
    parser.add_argument("--amp", action="store_true")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
