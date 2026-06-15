from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from sunpack.model_runtime.diagnosis.root_cases import ROOT_CASES, canonical_root_case


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = read_jsonl(args.input)
    output_rows = [add_evidence_targets(row) for row in rows]
    output = Path(args.output)
    write_jsonl(output, output_rows)
    summary = {
        "rows": len(output_rows),
        "rows_with_evidence_targets": sum(1 for row in output_rows if ((row.get("labels") or {}).get("auxiliary") or {}).get("root_evidence_targets")),
    }
    summary_path = Path(args.summary_output) if args.summary_output else output.with_name("diagnosis_evidence_rows_summary.json")
    write_json(summary_path, summary)
    print(json.dumps({"output": str(output), "summary": str(summary_path), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def add_evidence_targets(row: dict[str, Any]) -> dict[str, Any]:
    updated = dict(row)
    labels = dict(updated.get("labels") or {})
    root = labels.get("root_case") if isinstance(labels.get("root_case"), dict) else {}
    roots = [canonical_root_case(str(item or "")) for item in root.get("labels") or []]
    positives = {root for root in roots if root}
    if not positives:
        return updated
    targets = {root: (1.0 if root in positives else 0.0) for root in ROOT_CASES}
    auxiliary = dict(labels.get("auxiliary") or {})
    existing = auxiliary.get("root_evidence_targets") if isinstance(auxiliary.get("root_evidence_targets"), dict) else {}
    auxiliary["root_evidence_targets"] = dict(sorted({**existing, **targets}.items()))
    labels["auxiliary"] = auxiliary
    updated["labels"] = labels
    return updated


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Add root evidence reconstruction targets to DiagnosisGraph rows.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
