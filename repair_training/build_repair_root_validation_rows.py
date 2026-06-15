from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from collections import Counter
from pathlib import Path
from typing import Any

from repair_training.build_multi_field_damage_rows import _enforce_multi_field_target, build_multi_field_records
from repair_training.build_single_field_damage_rows import build_single_field_records
from repair_training.collect_damage_rows import collect_damage_rows
from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from sunpack.model_runtime.diagnosis.graph_dispatcher import build_diagnosis_graph_sample
from repair_training.core.diagnosis_graph.serialize import diagnosis_graph_summary
from sunpack.model_runtime.diagnosis.root_cases import ROOT_CASES, canonical_root_case
from repair_training.formats.zip.corruption_impl import single_field_fields


REPAIR_ROOT_VALIDATION_FIELDS: tuple[str, ...] = (
    "eocd.cd_offset",
    "eocd.cd_size",
    "eocd.entry_count",
    "eocd.comment_length",
    "central_directory.local_header_offset",
    "central_directory.flags",
    "central_directory.crc",
    "central_directory.compressed_size",
    "local_header.signature",
    "local_header.flags",
    "local_header.crc",
    "local_header.compressed_size",
    "central_directory.method",
    "local_header.method",
    "central_directory.filename",
    "local_header.filename",
    "central_directory.extra",
    "local_header.extra",
    "zip64.extra",
    "central_directory.extra_length",
    "local_header.extra_length",
    "data_descriptor.record",
    "data_descriptor.crc",
    "data_descriptor.size",
    "payload.compressed_data",
    "zip64.eocd",
    "zip64.locator",
    "zip64.extra_length",
    "zip64.uncompressed_size",
    "tail.trailing_bytes",
    "sfx_prefix.bytes",
    "split_volume.missing_range",
)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if str(args.format or "zip").lower() != "zip":
        raise SystemExit("repair-root validation rows currently support --format zip only")
    started = time.perf_counter()
    run_dir = Path(args.run_dir)
    datasets_dir = run_dir / "datasets"
    reports_dir = run_dir / "reports"
    workspace = Path(args.workspace) if args.workspace else run_dir / "tmp" / "repair_root_validation"
    datasets_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(parents=True, exist_ok=True)
    seed = _seed(args.seed)
    fields = _fields(args.fields)

    clean_rows = _load_clean_rows(Path(args.clean_rows), limit=max(0, int(args.clean_limit)), seed=seed)
    clean_graphs = [build_diagnosis_graph_sample(row).to_dict() for row in clean_rows]

    single_records, single_generation = build_balanced_single_field_records(
        material_root=Path(args.material_root),
        workspace=workspace / "single" / "generated",
        samples_per_root=max(0, int(args.single_per_root)),
        seed=seed + 11,
        fields=fields,
    ) if int(args.single_per_root) > 0 else ([], {"fields": fields, "samples_per_root": 0})
    single_rows, single_failures = collect_damage_rows(
        single_records,
        workspace=workspace / "single" / "observe",
        workers=max(1, int(args.workers)),
        config={},
    ) if single_records else ([], [])
    single_graphs = [build_diagnosis_graph_sample(row).to_dict() for row in single_rows]

    train_multi_records, train_multi_generation = build_multi_field_records(
        material_root=Path(args.material_root),
        workspace=workspace / "multi_train" / "generated",
        samples_per_size=max(0, int(args.multi_train_per_size)),
        seed=seed + 101,
        fields=fields,
        combo_sizes=_combo_sizes(args.train_combo_sizes),
    ) if int(args.multi_train_per_size) > 0 else ([], {"fields": fields, "samples_per_size": 0})
    train_multi_rows, train_multi_failures = collect_damage_rows(
        train_multi_records,
        workspace=workspace / "multi_train" / "observe",
        workers=max(1, int(args.workers)),
        config={},
    ) if train_multi_records else ([], [])
    train_multi_rows = [_enforce_multi_field_target(row) for row in train_multi_rows]
    train_multi_graphs = [build_diagnosis_graph_sample(row).to_dict() for row in train_multi_rows]

    test_multi_records, test_multi_generation = build_multi_field_records(
        material_root=Path(args.material_root),
        workspace=workspace / "multi_test" / "generated",
        samples_per_size=max(0, int(args.multi_test_per_size)),
        seed=seed + 1009,
        fields=fields,
        combo_sizes=_combo_sizes(args.test_combo_sizes),
    ) if int(args.multi_test_per_size) > 0 else ([], {"fields": fields, "samples_per_size": 0})
    test_multi_rows, test_multi_failures = collect_damage_rows(
        test_multi_records,
        workspace=workspace / "multi_test" / "observe",
        workers=max(1, int(args.workers)),
        config={},
    ) if test_multi_records else ([], [])
    test_multi_rows = [_enforce_multi_field_target(row) for row in test_multi_rows]
    test_multi_graphs = [build_diagnosis_graph_sample(row).to_dict() for row in test_multi_rows]

    train_graphs = [*clean_graphs, *single_graphs, *train_multi_graphs]
    prefix = str(args.output_prefix or "repair_root_validation")
    outputs = {
        "clean_graphs": datasets_dir / f"diagnosis_graph_{prefix}_clean_rows.jsonl",
        "single_rows": datasets_dir / f"{prefix}_single_rows.jsonl",
        "single_graphs": datasets_dir / f"diagnosis_graph_{prefix}_single_rows.jsonl",
        "multi_train_rows": datasets_dir / f"{prefix}_multi_train_rows.jsonl",
        "multi_train_graphs": datasets_dir / f"diagnosis_graph_{prefix}_multi_train_rows.jsonl",
        "multi_test_rows": datasets_dir / f"{prefix}_multi_test_rows.jsonl",
        "multi_test_graphs": datasets_dir / f"diagnosis_graph_{prefix}_multi_test_rows.jsonl",
        "train_graphs": datasets_dir / f"diagnosis_graph_{prefix}_train_rows.jsonl",
    }
    write_jsonl(outputs["clean_graphs"], clean_graphs)
    write_jsonl(outputs["single_rows"], single_rows)
    write_jsonl(outputs["single_graphs"], single_graphs)
    write_jsonl(outputs["multi_train_rows"], train_multi_rows)
    write_jsonl(outputs["multi_train_graphs"], train_multi_graphs)
    write_jsonl(outputs["multi_test_rows"], test_multi_rows)
    write_jsonl(outputs["multi_test_graphs"], test_multi_graphs)
    write_jsonl(outputs["train_graphs"], train_graphs)

    summary = {
        "schema_version": 1,
        "format": "zip",
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "fields": fields,
        "rows": {
            "clean": len(clean_rows),
            "single": len(single_rows),
            "multi_train": len(train_multi_rows),
            "multi_test": len(test_multi_rows),
            "train_total": len(train_graphs),
        },
        "failures": {
            "single": len(single_failures),
            "multi_train": len(train_multi_failures),
            "multi_test": len(test_multi_failures),
        },
        "labels": {
            "single": _root_label_counts(single_graphs),
            "multi_train": _root_label_counts(train_multi_graphs),
            "multi_test": _root_label_counts(test_multi_graphs),
            "train": _root_label_counts(train_graphs),
        },
        "generation": {
            "single": single_generation,
            "multi_train": train_multi_generation,
            "multi_test": test_multi_generation,
        },
        "graphs": {
            "train": diagnosis_graph_summary([build_diagnosis_graph_sample(row) for row in [*clean_rows, *single_rows, *train_multi_rows]]),
            "multi_test": diagnosis_graph_summary([build_diagnosis_graph_sample(row) for row in test_multi_rows]),
        },
        "outputs": {name: str(path) for name, path in outputs.items()},
    }
    summary_path = reports_dir / f"{prefix}_summary.json"
    write_json(summary_path, summary)
    print(json.dumps({"summary": str(summary_path), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def _load_clean_rows(path: Path, *, limit: int, seed: int) -> list[dict[str, Any]]:
    rows = read_jsonl(path)
    if limit == 0:
        return []
    if limit <= 0 or len(rows) <= limit:
        return rows
    rng = random.Random(seed)
    indices = sorted(rng.sample(range(len(rows)), limit))
    return [rows[index] for index in indices]


def _root_label_counts(graph_rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in graph_rows:
        labels = ((row.get("labels") or {}).get("root_case") or {}).get("labels") or []
        for label in labels:
            counts[str(label)] += 1
    return dict(sorted(counts.items()))


def build_balanced_single_field_records(
    *,
    material_root: Path,
    workspace: Path,
    samples_per_root: int,
    seed: int,
    fields: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if samples_per_root <= 0:
        return [], {"fields": fields, "samples_per_root": 0}
    by_root: dict[str, list[str]] = {root: [] for root in ROOT_CASES}
    for field in fields:
        root = canonical_root_case(field)
        if root:
            by_root.setdefault(root, []).append(field)
    records: list[dict[str, Any]] = []
    reports: dict[str, Any] = {}
    for root in ROOT_CASES:
        root_fields = sorted(set(by_root.get(root) or []))
        if not root_fields:
            reports[root] = {"reason": "no_mutation_field"}
            continue
        per_field = max(1, (samples_per_root + len(root_fields) - 1) // len(root_fields))
        root_records, report = build_single_field_records(
            material_root=material_root,
            workspace=workspace / root,
            samples_per_field=per_field,
            seed=seed + int(hashlib.sha256(root.encode("utf-8")).hexdigest()[:8], 16) % 100000,
            fields=root_fields,
        )
        selected = root_records[:samples_per_root]
        records.extend(selected)
        reports[root] = {
            "fields": root_fields,
            "requested": samples_per_root,
            "generated": len(selected),
            "raw_generated": len(root_records),
            "generation": report,
        }
    return records, {
        "fields": fields,
        "root_cases": list(ROOT_CASES),
        "samples_per_root": samples_per_root,
        "generated_by_root": {
            root: sum(1 for record in records if canonical_root_case(str(record.get("single_field_root") or "")) == root)
            for root in ROOT_CASES
        },
        "per_root": reports,
    }


def _fields(raw: str) -> list[str]:
    if not str(raw or "").strip():
        return list(REPAIR_ROOT_VALIDATION_FIELDS)
    requested = [item.strip() for item in str(raw).split(",") if item.strip()]
    unknown = [item for item in requested if item not in set(single_field_fields())]
    if unknown:
        raise SystemExit(f"unknown single-field ZIP fields: {', '.join(unknown)}")
    return requested


def _combo_sizes(raw: str) -> list[int]:
    return sorted({int(item.strip()) for item in str(raw or "").split(",") if item.strip() and int(item.strip()) >= 2})


def _seed(value: str) -> int:
    if str(value or "").lower() == "random":
        return random.randrange(1, 2**31 - 1)
    return int(value or 20260518)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a fast ZIP DiagnosisGNN validation corpus balanced around repair-meaningful root fields.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--clean-rows", default=str(Path("repair_training") / "runs" / "zip" / "20260518_zip64_eocd_locator_singlefield" / "datasets" / "normal_structure_rows.jsonl"))
    parser.add_argument("--workspace", default="")
    parser.add_argument("--output-prefix", default="repair_root_validation")
    parser.add_argument("--clean-limit", type=int, default=120)
    parser.add_argument("--single-per-root", type=int, default=3)
    parser.add_argument("--multi-train-per-size", type=int, default=60)
    parser.add_argument("--multi-test-per-size", type=int, default=30)
    parser.add_argument("--train-combo-sizes", default="2,3")
    parser.add_argument("--test-combo-sizes", default="2,3,4")
    parser.add_argument("--fields", default="")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--seed", default="20260518")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
