from __future__ import annotations

import argparse
from pathlib import Path

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.repair_policy_transformer.dataset import read_policy_graph_samples, read_policy_world_samples
from sunpack.model_runtime.policy.inference import RepairPolicyTransformerModel
from repair_training.core.repair_policy_transformer.metrics import policy_teacher_metrics
from sunpack.model_runtime.policy.tensorize import tensorize_world_sample


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    model = RepairPolicyTransformerModel(model_dir=args.model_dir, device=args.device)
    raw_rows = read_jsonl(args.input)
    if raw_rows and any(row.get("task") for row in raw_rows):
        return _evaluate_world(args, model)
    rows = []
    for sample in read_policy_graph_samples(args.input):
        pred = model.predict_sample(sample)
        pred["sample_id"] = sample.sample_id
        labels = {action.action_id: action.to_dict() for action in sample.actions}
        labels.update({f"{action.action_type}:{action.action_id}": action.to_dict() for action in sample.actions})
        for action in pred.get("action_scores") or []:
            label = labels.get(str(action.get("action_id") or "")) or labels.get(f"{action.get('action_type')}:{action.get('action_id')}")
            if label:
                action["action_q_value"] = label.get("action_q_value", 0.0)
                action["action_prior"] = label.get("action_prior", 0.0)
        pred["has_promising_future"] = sample.has_promising_future
        pred["stop_regret"] = sample.stop_regret
        rows.append(pred)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "predictions.jsonl", rows)
    write_json(output / "metrics.json", policy_teacher_metrics(rows))
    return 0


def _evaluate_world(args, model: RepairPolicyTransformerModel) -> int:
    rows = []
    transition_errors = []
    mask_errors = []
    for sample in read_policy_world_samples(args.input):
        pred = model.predict_world_sample(sample)
        if sample.task == "transition":
            target = tensorize_world_sample(sample)["transition_target"].tolist()
            transition_errors.append(_mse(pred.get("transition_prediction") or [], target))
        if sample.task == "masked_graph":
            target = _mask_target(sample.mask_targets)
            mask_errors.append(_mse(pred.get("masked_prediction") or [], target))
        pred["has_promising_future"] = bool(sample.ranking_sample.has_promising_future) if sample.ranking_sample else False
        pred["stop_regret"] = float(sample.ranking_sample.stop_regret) if sample.ranking_sample else 0.0
        rows.append(pred)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "predictions.jsonl", rows)
    policy_rows = [row for row in rows if row.get("action_scores")]
    metrics = policy_teacher_metrics(policy_rows)
    metrics.update({
        "world_samples": len(rows),
        "transition_prediction_mse": sum(transition_errors) / max(1, len(transition_errors)),
        "masked_graph_mse": sum(mask_errors) / max(1, len(mask_errors)),
        "transition_samples": len(transition_errors),
        "masked_graph_samples": len(mask_errors),
    })
    write_json(output / "metrics.json", metrics)
    return 0


def _mask_target(targets: dict) -> list[float]:
    return [
        _float(targets.get("recovery_score")),
        _hash_unit(targets.get("patch_status")),
        _float(targets.get("diagnosis_max_score")),
        1.0 if targets.get("is_best_node") else 0.0,
    ]


def _mse(predicted: list[float], target: list[float]) -> float:
    values = list(zip(predicted, target))
    if not values:
        return 0.0
    return sum((float(left) - float(right)) ** 2 for left, right in values) / len(values)


def _hash_unit(value, *, buckets: int = 2048) -> float:
    import hashlib

    text = str(value or "")
    if not text:
        return 0.0
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return (int(digest[:8], 16) % buckets) / float(buckets - 1)


def _float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate RepairGraph Memory Policy Transformer.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
