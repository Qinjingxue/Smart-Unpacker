from __future__ import annotations

import argparse
import json
from pathlib import Path

from repair_training.data.io import read_jsonl, write_json, write_jsonl
from sunpack.repair.model.diagnosis.graph_dispatcher import (
    UnsupportedDiagnosisGraphFormat,
    build_diagnosis_graph_sample,
    build_diagnosis_graph_sample_for_format,
    detect_graph_format,
)
from repair_training.diagnosis.serialize import diagnosis_graph_summary
from repair_training.formats.base import normalize_format_name


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    requested_format = str(args.format or "auto").strip().lower()
    rows = read_jsonl(args.input)
    samples = []
    unsupported: list[dict[str, str]] = []
    for index, row in enumerate(rows):
        try:
            if requested_format == "auto":
                sample = build_diagnosis_graph_sample(row)
            else:
                detected = detect_graph_format(row)
                expected = normalize_format_name(requested_format)
                if detected != expected:
                    raise SystemExit(f"row {index} format mismatch: requested {expected}, detected {detected}")
                sample = build_diagnosis_graph_sample_for_format(expected, row)
            samples.append(sample)
        except UnsupportedDiagnosisGraphFormat as exc:
            if requested_format != "auto":
                raise SystemExit(str(exc)) from exc
            unsupported.append({"row_index": str(index), "error": str(exc)})
    output = Path(args.output)
    write_jsonl(output, [sample.to_dict() for sample in samples])
    summary_path = Path(args.summary_output) if args.summary_output else output.parent.parent / "reports" / "diagnosis_graph_summary.json"
    summary = diagnosis_graph_summary(samples, unsupported_count=len(unsupported))
    if unsupported:
        summary["unsupported"] = unsupported[:100]
    write_json(summary_path, summary)
    print(json.dumps({
        "input": str(args.input),
        "output": str(output),
        "summary": str(summary_path),
        **summary,
    }, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build DiagnosisGraph JSONL rows from ArchiveKnowledge rows.")
    parser.add_argument("--format", default="auto", help="auto or a supported format such as zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
