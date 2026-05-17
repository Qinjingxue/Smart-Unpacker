from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from repair_training.core.normal_structure_inference import NormalStructureModel
from repair_training.core.plugin import load_training_format_plugin, normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    plugin = load_training_format_plugin(fmt)
    model = NormalStructureModel(model_dir=args.normal_model_dir, plugin=plugin)
    rows = read_jsonl(args.input)
    output_rows: list[dict[str, Any]] = []
    for row in rows:
        payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else {}
        world = model.analyze_knowledge(payload)
        out = dict(row)
        out["world_model"] = {
            "world_field_scores": dict(world.get("world_field_scores") or {}),
            "world_field_predictions": dict(world.get("world_field_predictions") or {}),
            "world_summary": dict(world.get("world_summary") or {}),
            "structure_anomaly": dict(world.get("structure_anomaly") or {}),
        }
        out.setdefault("metadata", {})
        if isinstance(out["metadata"], dict):
            out["metadata"]["normal_structure_applied"] = True
        output_rows.append(out)
    write_jsonl(args.output, output_rows)
    summary = {
        "schema_version": 1,
        "format": fmt,
        "rows": len(output_rows),
        "input": str(args.input),
        "output": str(args.output),
        "normal_model_dir": str(args.normal_model_dir),
    }
    summary_path = Path(args.summary_output) if args.summary_output else Path(args.output).with_name("apply_normal_structure_summary.json")
    write_json(summary_path, summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inject NormalStructureModel anomaly payload into damage rows.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--normal-model-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
