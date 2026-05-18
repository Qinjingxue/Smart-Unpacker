from __future__ import annotations

import argparse
from pathlib import Path

from repair_training.core.datasets import write_json, write_jsonl
from repair_training.core.repair_policy_transformer.dataset import read_policy_graph_samples
from repair_training.core.repair_policy_transformer.inference import RepairPolicyTransformerModel


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    model = RepairPolicyTransformerModel(model_dir=args.model_dir, device=args.device)
    rows = []
    for sample in read_policy_graph_samples(args.input):
        pred = model.predict_sample(sample)
        pred["sample_id"] = sample.sample_id
        rows.append(pred)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "predictions.jsonl", rows)
    write_json(output / "metrics.json", {"samples": len(rows)})
    return 0


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

