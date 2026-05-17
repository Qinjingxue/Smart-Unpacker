from __future__ import annotations

import argparse
import json
import random
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from repair_training.collect_damage_rows import collect_damage_rows
from repair_training.core.datasets import write_json, write_jsonl
from repair_training.core.diagnosis_graph.dispatcher import build_diagnosis_graph_sample
from repair_training.core.diagnosis_graph.serialize import diagnosis_graph_summary
from repair_training.core.features import damage_labels_for_row
from repair_training.formats.zip.build_material_impl import (
    _apply_profile_metadata,
    _distributed_zip_sources,
    _profile_layer_name,
    _source_compatible_with_profile,
)
from repair_training.formats.zip.corruption_impl import (
    build_corpus_corruption_case,
    single_field_fields,
    single_field_profile_for_field,
)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if str(args.format or "zip").lower() != "zip":
        raise SystemExit("single-field damage rows currently support --format zip only")
    run_root = _run_root(Path(args.output))
    workspace = Path(args.workspace) if args.workspace else run_root / "tmp" / "single_field_damage_rows"
    workspace.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    records, generation_report = build_single_field_records(
        material_root=Path(args.material_root),
        workspace=workspace / "generated",
        samples_per_field=max(1, int(args.samples_per_field)),
        seed=_seed(args.seed),
        fields=_selected_fields(args.fields),
    )
    rows, failures = collect_damage_rows(
        records,
        workspace=workspace / "observe",
        workers=max(1, int(args.workers)),
        config={},
    )
    graph_samples = [build_diagnosis_graph_sample(row) for row in rows]
    row_output = Path(args.output)
    graph_output = Path(args.graph_output) if args.graph_output else row_output.with_name("diagnosis_graph_single_field_rows.jsonl")
    failure_output = Path(args.failure_output) if args.failure_output else row_output.with_name("single_field_failures.jsonl")
    summary_output = Path(args.summary_output) if args.summary_output else row_output.with_name("single_field_summary.json")
    report_output = Path(args.per_field_report_output) if args.per_field_report_output else row_output.with_name("single_field_per_field_report.json")
    write_jsonl(row_output, rows)
    write_jsonl(graph_output, [sample.to_dict() for sample in graph_samples])
    write_jsonl(failure_output, failures)
    per_field_report = _per_field_report(rows, failures, generation_report)
    summary = {
        "schema_version": 1,
        "format": "zip",
        "rows": len(rows),
        "failures": len(failures),
        "records_generated": len(records),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "samples_per_field": max(1, int(args.samples_per_field)),
        "outputs": {
            "rows": str(row_output),
            "graphs": str(graph_output),
            "failures": str(failure_output),
            "per_field_report": str(report_output),
        },
        "generation": generation_report,
        "graphs": diagnosis_graph_summary(graph_samples),
    }
    write_json(summary_output, summary)
    write_json(report_output, per_field_report)
    print(json.dumps({"output": str(row_output), "graph_output": str(graph_output), "summary": str(summary_output), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def build_single_field_records(
    *,
    material_root: Path,
    workspace: Path,
    samples_per_field: int,
    seed: int,
    fields: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rng = random.Random(seed)
    sources = _distributed_zip_sources(material_root / "zip", set())
    records: list[dict[str, Any]] = []
    skipped: dict[str, dict[str, Any]] = {}
    attempts_by_field: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    variant_counts: Counter[str] = Counter()
    for field in fields:
        profile = single_field_profile_for_field(field)
        compatible = [source for source in sources if _source_compatible_with_profile(dict(source.get("source_derivation") or {}), profile)]
        if not compatible:
            skipped[field] = {"reason": "no_compatible_source", "profile": profile}
            continue
        candidate_sources = list(compatible)
        while _field_record_count(records, field) < samples_per_field and candidate_sources:
            min_count = min(source_counts[str(item["source"])] for item in candidate_sources)
            least_used = [item for item in candidate_sources if source_counts[str(item["source"])] == min_count]
            source_item = dict(rng.choice(least_used))
            source = Path(source_item["source"])
            source_key = str(source)
            attempts_by_field[field] += 1
            variant_index = int(variant_counts[source_key])
            try:
                case = build_corpus_corruption_case(
                    workspace / _safe_name(field) / str(source_item.get("source_archive_id") or source.stem) / f"v{variant_index:04d}",
                    source_path=source,
                    fmt="zip",
                    seed=rng.randrange(1, 2**31 - 1),
                    variant_index=variant_index,
                    damage_profile=profile,
                    source_derivation=dict(source_item.get("source_derivation") or {}),
                    password=_source_password(source_item),
                )
            except Exception as exc:
                candidate_sources = [item for item in candidate_sources if Path(item["source"]) != source]
                skipped.setdefault(field, {"profile": profile, "unsupported_source_count": 0, "errors": []})
                skipped[field]["unsupported_source_count"] = int(skipped[field].get("unsupported_source_count") or 0) + 1
                skipped[field].setdefault("errors", []).append({"source": str(source), "error": str(exc)})
                continue
            variant_counts[source_key] += 1
            source_counts[source_key] += 1
            record = case.corpus_manifest_record(
                source_archive_id=str(source_item.get("source_archive_id") or source.stem),
                source_path=str(source),
                damage_profile=profile,
                variant_index=variant_index,
                material_format="zip",
                material_sample_id=str(Path(source_item.get("sample_dir") or "").name),
            )
            password = _source_password(source_item)
            if password and not record.get("password"):
                record["password"] = password
            record["source_derivation"] = dict(source_item.get("source_derivation") or {})
            record["damage_layer"] = "single_field"
            record["requested_damage_layer"] = "single_field"
            record["actual_damage_layer"] = "single_field"
            record["damage_layer_weight"] = 1.0
            record["single_field_root"] = field
            record["expected_min_steps"] = 1
            _apply_profile_metadata(record, profile, {"profile_layer": "single_field", "compound_profile": False})
            records.append(record)
        if _field_record_count(records, field) < samples_per_field:
            skipped.setdefault(field, {"profile": profile})
            skipped[field]["reason"] = "insufficient_supported_sources"
            skipped[field]["requested"] = samples_per_field
            skipped[field]["generated"] = _field_record_count(records, field)
    report = {
        "fields": fields,
        "samples_per_field": samples_per_field,
        "generated_by_field": dict(sorted(Counter(record["single_field_root"] for record in records).items())),
        "attempts_by_field": dict(sorted(attempts_by_field.items())),
        "skipped": skipped,
        "source_count": len(sources),
    }
    return records, report


def _per_field_report(rows: list[dict[str, Any]], failures: list[dict[str, Any]], generation_report: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    row_counts: Counter[str] = Counter()
    for row in rows:
        field = str((row.get("metadata") or {}).get("raw_damage_record", {}).get("single_field_root") or "")
        if not field:
            raw = (row.get("metadata") or {}).get("raw_damage_record") or {}
            field = str(raw.get("single_field_root") or "")
        row_counts[field] += 1
        for label in damage_labels_for_row(row):
            counts[field][label] += 1
    return {
        "rows_by_field": dict(sorted(row_counts.items())),
        "labels_by_field": {field: dict(sorted(counter.items())) for field, counter in sorted(counts.items())},
        "failures": len(failures),
        "generation": generation_report,
    }


def _field_record_count(records: list[dict[str, Any]], field: str) -> int:
    return sum(1 for record in records if record.get("single_field_root") == field)


def _source_password(source_item: dict[str, Any]) -> str | None:
    derivation = source_item.get("source_derivation") if isinstance(source_item.get("source_derivation"), dict) else {}
    password = str(derivation.get("zip_password") or "")
    return password or None


def _selected_fields(raw: str) -> list[str]:
    if not raw.strip():
        return list(single_field_fields())
    requested = [item.strip() for item in raw.split(",") if item.strip()]
    allowed = set(single_field_fields())
    unknown = [item for item in requested if item not in allowed]
    if unknown:
        raise SystemExit(f"unknown single-field ZIP fields: {', '.join(unknown)}")
    return requested


def _run_root(output: Path) -> Path:
    return output.parents[1] if output.parent.name == "datasets" and len(output.parents) > 1 else output.parent


def _seed(value: str) -> int:
    if str(value or "").lower() == "random":
        return random.randrange(1, 2**31 - 1)
    return int(value or 20260517)


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)[:120] or "field"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build real ZIP single-field damage rows through the main analysis/extraction/verification pipeline.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--graph-output", default="")
    parser.add_argument("--failure-output", default="")
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--per-field-report-output", default="")
    parser.add_argument("--workspace", default="")
    parser.add_argument("--samples-per-field", type=int, default=30)
    parser.add_argument("--fields", default="")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--seed", default="20260517")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
