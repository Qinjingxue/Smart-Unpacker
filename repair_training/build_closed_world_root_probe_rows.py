from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from sunpack.model_runtime.diagnosis.root_cases import ROOT_CASES, canonical_root_case


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = read_jsonl(args.graphs)
    probes = build_closed_world_probe_rows(rows)
    output = Path(args.output)
    write_jsonl(output, probes)
    summary = {
        "schema": "closed_world_root_probe_rows_v1",
        "graph_rows": len(rows),
        "probe_rows": len(probes),
        "roots": list(ROOT_CASES),
        "positive_probe_rows": sum(1 for row in probes if _score(row) > 0.0),
    }
    summary_path = Path(args.summary_output) if args.summary_output else output.with_name(f"{output.stem}_summary.json")
    write_json(summary_path, summary)
    print(json.dumps({"output": str(output), "summary": str(summary_path), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def build_closed_world_probe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        sample_id = str(row.get("sample_id") or "")
        if not sample_id:
            continue
        positives = set(_root_labels(row))
        if not positives:
            continue
        for root in ROOT_CASES:
            value = 1.0 if root in positives else 0.0
            output.append({
                "graph_sample_id": sample_id,
                "candidate_root": root,
                "recovery_delta": value,
                "ak_consistency_delta": value,
                "evidence_delta": value,
                "preference_group_id": sample_id,
                "synthetic_probe": True,
                "closed_world": True,
            })
    return output


def _root_labels(row: dict[str, Any]) -> list[str]:
    labels = row.get("labels") if isinstance(row.get("labels"), dict) else {}
    root = labels.get("root_case") if isinstance(labels.get("root_case"), dict) else {}
    raw = root.get("labels") or root.get("root_case_labels") or []
    output = []
    for item in raw:
        root_name = canonical_root_case(str(item or ""))
        if root_name:
            output.append(root_name)
    return sorted(set(output))


def _score(row: dict[str, Any]) -> float:
    return max(float(row.get("recovery_delta") or 0.0), float(row.get("ak_consistency_delta") or 0.0), float(row.get("evidence_delta") or 0.0))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build closed-world root hypothesis probe rows from DiagnosisGraph labels.")
    parser.add_argument("--graphs", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
