from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import write_json, write_jsonl
from repair_training.core.diagnosis_gnn.actionable_roots import modules_for_root
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples
from repair_training.core.diagnosis_gnn.inference import DiagnosisGNNModel


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    samples = read_diagnosis_graph_samples(args.input)
    model = DiagnosisGNNModel(model_dir=args.model_dir, device=args.device)
    predictions = model.predict_samples(samples)
    rows = []
    top_hits = {1: 0, 3: 0, 5: 0}
    module_hits = {1: 0, 3: 0, 5: 0}
    labeled = 0
    for sample, prediction in zip(samples, predictions):
        truth_roots = set(sample.labels.root_case_labels)
        if not truth_roots:
            continue
        labeled += 1
        root = prediction.get("root_case") if isinstance(prediction.get("root_case"), dict) else {}
        ranked_roots = [str(item.get("root_case") or "") for item in root.get("ranked") or [] if isinstance(item, dict)]
        truth_modules = set(_modules_for_roots(truth_roots))
        ranked_modules = _modules_for_roots(ranked_roots)
        row = {
            "sample_id": sample.sample_id,
            "truth_roots": sorted(truth_roots),
            "truth_modules": sorted(truth_modules),
            "ranked_roots": ranked_roots[:10],
            "ranked_modules": ranked_modules[:10],
        }
        for k in top_hits:
            top_hits[k] += int(bool(set(ranked_roots[:k]) & truth_roots))
            module_hits[k] += int(bool(set(ranked_modules[:k]) & truth_modules))
        rows.append(row)
    metrics = {
        "rows": len(samples),
        "labeled_rows": labeled,
        "root_top1_hit": top_hits[1] / max(1, labeled),
        "root_top3_hit": top_hits[3] / max(1, labeled),
        "root_top5_hit": top_hits[5] / max(1, labeled),
        "module_direction_top1_hit": module_hits[1] / max(1, labeled),
        "module_direction_top3_hit": module_hits[3] / max(1, labeled),
        "module_direction_top5_hit": module_hits[5] / max(1, labeled),
    }
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "hgt_only_policy_predictions.jsonl", rows)
    write_json(output / "hgt_only_policy_metrics.json", metrics)
    print(json.dumps({"output": str(output), "metrics": metrics}, ensure_ascii=False, sort_keys=True))
    return 0


def _modules_for_roots(roots: set[str] | list[str]) -> list[str]:
    modules: list[str] = []
    seen: set[str] = set()
    for root in roots:
        for module in modules_for_root(str(root)):
            if module not in seen:
                seen.add(module)
                modules.append(module)
    return modules


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate whether Diagnosis HGT root scores alone identify useful module directions.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
