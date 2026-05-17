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
    _oracle_from_clean_bytes,
    _safe_zip_cd_offset,
    _single_field_damage_flags,
    _write_corpus_case,
    _zip_central_directory_header_offsets,
    _zip_entry_infos,
    _zip_single_field_mutations,
    apply_mutations,
    single_field_fields,
    single_field_profile_for_field,
)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if str(args.format or "zip").lower() != "zip":
        raise SystemExit("multi-field damage rows currently support --format zip only")
    run_root = _run_root(Path(args.output))
    workspace = Path(args.workspace) if args.workspace else run_root / "tmp" / "multi_field_damage_rows"
    workspace.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    combo_sizes = _combo_sizes(args.combo_sizes)
    records, generation_report = build_multi_field_records(
        material_root=Path(args.material_root),
        workspace=workspace / "generated",
        samples_per_size=max(1, int(args.samples_per_size)),
        seed=_seed(args.seed),
        fields=_selected_fields(args.fields),
        combo_sizes=combo_sizes,
    )
    rows, failures = collect_damage_rows(
        records,
        workspace=workspace / "observe",
        workers=max(1, int(args.workers)),
        config={},
    )
    rows = [_enforce_multi_field_target(row) for row in rows]
    graph_samples = [build_diagnosis_graph_sample(row) for row in rows]
    row_output = Path(args.output)
    graph_output = Path(args.graph_output) if args.graph_output else row_output.with_name("diagnosis_graph_multi_field_rows.jsonl")
    failure_output = Path(args.failure_output) if args.failure_output else row_output.with_name("multi_field_failures.jsonl")
    summary_output = Path(args.summary_output) if args.summary_output else row_output.with_name("multi_field_summary.json")
    report_output = Path(args.per_combo_report_output) if args.per_combo_report_output else row_output.with_name("multi_field_per_combo_report.json")
    write_jsonl(row_output, rows)
    write_jsonl(graph_output, [sample.to_dict() for sample in graph_samples])
    write_jsonl(failure_output, failures)
    per_combo_report = _per_combo_report(rows, failures, generation_report)
    summary = {
        "schema_version": 1,
        "format": "zip",
        "rows": len(rows),
        "failures": len(failures),
        "records_generated": len(records),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "samples_per_size": max(1, int(args.samples_per_size)),
        "combo_sizes": combo_sizes,
        "outputs": {
            "rows": str(row_output),
            "graphs": str(graph_output),
            "failures": str(failure_output),
            "per_combo_report": str(report_output),
        },
        "generation": generation_report,
        "graphs": diagnosis_graph_summary(graph_samples),
    }
    write_json(summary_output, summary)
    write_json(report_output, per_combo_report)
    print(json.dumps({"output": str(row_output), "graph_output": str(graph_output), "summary": str(summary_output), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def build_multi_field_records(
    *,
    material_root: Path,
    workspace: Path,
    samples_per_size: int,
    seed: int,
    fields: list[str],
    combo_sizes: list[int],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rng = random.Random(seed)
    sources = _distributed_zip_sources(material_root / "zip", set())
    records: list[dict[str, Any]] = []
    skipped: dict[str, Any] = {}
    attempts_by_size: Counter[int] = Counter()
    generated_by_size: Counter[int] = Counter()
    source_counts: Counter[str] = Counter()
    variant_counts: Counter[str] = Counter()
    compatible_by_field: dict[str, list[dict[str, Any]]] = {
        field: [
            source for source in sources
            if _source_compatible_with_profile(dict(source.get("source_derivation") or {}), single_field_profile_for_field(field))
        ]
        for field in fields
    }
    for size in combo_sizes:
        target = samples_per_size
        failed_attempts = 0
        while generated_by_size[size] < target and failed_attempts < target * 80:
            attempts_by_size[size] += 1
            failed_attempts += 1
            combo = tuple(sorted(rng.sample(fields, min(size, len(fields)))))
            compatible = _compatible_sources_for_combo(combo, compatible_by_field)
            if not compatible:
                skipped.setdefault(str(size), {})
                skipped[str(size)]["no_compatible_combo_count"] = int(skipped[str(size)].get("no_compatible_combo_count") or 0)
                skipped[str(size)].setdefault("examples", [])
                skipped[str(size)]["no_compatible_combo_count"] += 1
                if len(skipped[str(size)]["examples"]) < 8:
                    skipped[str(size)]["examples"].append(list(combo))
                continue
            min_count = min(source_counts[str(item["source"])] for item in compatible)
            least_used = [item for item in compatible if source_counts[str(item["source"])] == min_count]
            source_item = dict(rng.choice(least_used))
            source = Path(source_item["source"])
            source_key = str(source)
            variant_index = int(variant_counts[source_key])
            try:
                case = _build_combo_case(
                    workspace / f"{size}_fields" / _safe_name("__".join(combo)) / str(source_item.get("source_archive_id") or source.stem) / f"v{variant_index:04d}",
                    source=source,
                    fields=list(combo),
                    seed=rng.randrange(1, 2**31 - 1),
                    variant_index=variant_index,
                    password=_source_password(source_item),
                )
            except Exception as exc:
                skipped.setdefault(str(size), {})
                skipped[str(size)].setdefault("build_errors", [])
                if len(skipped[str(size)]["build_errors"]) < 20:
                    skipped[str(size)]["build_errors"].append({"fields": list(combo), "source": str(source), "error": str(exc)})
                continue
            variant_counts[source_key] += 1
            source_counts[source_key] += 1
            generated_by_size[size] += 1
            record = case.corpus_manifest_record(
                source_archive_id=str(source_item.get("source_archive_id") or source.stem),
                source_path=str(source),
                damage_profile=f"multi_field_{size}",
                variant_index=variant_index,
                material_format="zip",
                material_sample_id=str(Path(source_item.get("sample_dir") or "").name),
            )
            password = _source_password(source_item)
            if password and not record.get("password"):
                record["password"] = password
            record["source_derivation"] = dict(source_item.get("source_derivation") or {})
            record["damage_layer"] = "multi_field"
            record["requested_damage_layer"] = "multi_field"
            record["actual_damage_layer"] = "multi_field"
            record["damage_layer_weight"] = 1.0
            record["multi_field_roots"] = list(combo)
            record["multi_field_count"] = size
            record["expected_min_steps"] = size
            _apply_profile_metadata(record, f"multi_field_{size}", {"profile_layer": "compound", "compound_profile": True})
            metadata = dict(record.get("metadata") or {})
            metadata["multi_field_roots"] = list(combo)
            metadata["multi_field_count"] = size
            record["metadata"] = metadata
            records.append(record)
        if generated_by_size[size] < target:
            skipped.setdefault(str(size), {})["reason"] = "insufficient_supported_combinations"
            skipped[str(size)]["requested"] = target
            skipped[str(size)]["generated"] = generated_by_size[size]
    report = {
        "fields": fields,
        "combo_sizes": combo_sizes,
        "samples_per_size": samples_per_size,
        "generated_by_size": {str(k): v for k, v in sorted(generated_by_size.items())},
        "attempts_by_size": {str(k): v for k, v in sorted(attempts_by_size.items())},
        "skipped": skipped,
        "source_count": len(sources),
    }
    return records, report


def _build_combo_case(root: Path, *, source: Path, fields: list[str], seed: int, variant_index: int, password: str | None) -> Any:
    clean = source.read_bytes()
    current = clean
    mutations = []
    flags = ["multi_field_root_cause", f"multi_field_count:{len(fields)}"]
    rng = random.Random(int(seed) + int(variant_index) * 1009)
    ordered_fields = _mutation_order(fields)
    for field in ordered_fields:
        entry_infos = _zip_entry_infos(current)
        eocd = current.rfind(b"PK\x05\x06")
        cd_offset = _safe_zip_cd_offset(current)
        cd_headers = _zip_central_directory_header_offsets(current, cd_offset, eocd)
        field_mutations = _zip_single_field_mutations(current, entry_infos, cd_headers, eocd, rng, field)
        if not field_mutations:
            raise ValueError(f"multi-field ZIP profile is unsupported for this source after prior mutations: {field}")
        mutation = field_mutations[0]
        mutations.append(mutation)
        current = apply_mutations(current, [mutation])
        flags.extend(_single_field_damage_flags(field))
    oracle = _oracle_from_clean_bytes(clean, "zip")
    case_id = f"{source.stem}_multi_field_{len(fields)}_{variant_index}_{'_'.join(_safe_name(field) for field in ordered_fields)}"
    return _write_corpus_case(
        root,
        _safe_name(case_id),
        "zip",
        clean,
        current,
        mutations,
        seed=seed,
        damage_flags=_dedupe(flags),
        expected_statuses=("repaired", "partial", "unrepairable", "unsupported"),
        expected_files=oracle.get("expected_files", oracle.get("files", {})),
        expected_payload=oracle.get("payload", b""),
        expected_bytes=clean if oracle.get("bytes_exact") else b"",
        output_required=False,
        builder_call="build_multi_field_damage_rows",
        oracle_strength=str(oracle.get("oracle_strength") or "bytes_exact"),
        profile_capability="multi_field_structural",
        difficulty_tags=["multi_field_damage", "multi_round_repair_expected"],
        password=password,
    )


def _mutation_order(fields: list[str]) -> list[str]:
    priority = {
        "zip64.": 0,
        "data_descriptor.": 1,
        "central_directory.": 2,
        "local_header.": 3,
        "eocd.": 4,
        "tail.": 5,
        "sfx_prefix.": 6,
        "split_volume.": 7,
    }
    return sorted(fields, key=lambda field: next((rank for prefix, rank in priority.items() if field.startswith(prefix)), 99))


def _compatible_sources_for_combo(combo: tuple[str, ...], compatible_by_field: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    if not combo:
        return []
    source_sets = [set(str(item["source"]) for item in compatible_by_field.get(field, [])) for field in combo]
    shared = set.intersection(*source_sets) if source_sets else set()
    first = compatible_by_field.get(combo[0], [])
    return [item for item in first if str(item["source"]) in shared]


def _per_combo_report(rows: list[dict[str, Any]], failures: list[dict[str, Any]], generation_report: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    row_counts: Counter[str] = Counter()
    for row in rows:
        raw = (row.get("metadata") or {}).get("raw_damage_record") or {}
        fields = list(raw.get("multi_field_roots") or row.get("multi_field_roots") or [])
        key = f"{len(fields)}:" + ",".join(fields)
        row_counts[key] += 1
        for label in damage_labels_for_row(row):
            counts[key][label] += 1
    return {
        "rows_by_combo": dict(sorted(row_counts.items())),
        "labels_by_combo": {combo: dict(sorted(counter.items())) for combo, counter in sorted(counts.items())},
        "failures": len(failures),
        "generation": generation_report,
    }


def _enforce_multi_field_target(row: dict[str, Any]) -> dict[str, Any]:
    raw = (row.get("metadata") or {}).get("raw_damage_record") or {}
    fields = [str(field) for field in raw.get("multi_field_roots") or row.get("multi_field_roots") or [] if str(field)]
    if not fields:
        return row
    target = dict(row.get("damage_analysis_target") or {})
    labels = sorted({*(str(label) for label in target.get("damage_labels") or []), *(f"field:{field}" for field in fields), *(f"zone:{field.split('.', 1)[0]}" for field in fields)})
    observed = sorted({*(str(label) for label in target.get("observed_labels") or []), *labels})
    target["damage_labels"] = labels
    target["observed_labels"] = observed
    target["labels"] = [{"label": label, "confidence": 1.0, "source": "multi_field_roots"} for label in labels]
    row["damage_analysis_target"] = target
    row["oracle_damage"] = [{"label": label, "confidence": 1.0, "source": "multi_field_roots"} for label in labels]
    return row


def _selected_fields(raw: str) -> list[str]:
    if not raw.strip():
        return list(single_field_fields())
    requested = [item.strip() for item in raw.split(",") if item.strip()]
    allowed = set(single_field_fields())
    unknown = [item for item in requested if item not in allowed]
    if unknown:
        raise SystemExit(f"unknown single-field ZIP fields: {', '.join(unknown)}")
    return requested


def _combo_sizes(raw: str) -> list[int]:
    output = [int(item.strip()) for item in str(raw or "2,3,4").split(",") if item.strip()]
    return sorted({value for value in output if value >= 2})


def _source_password(source_item: dict[str, Any]) -> str | None:
    derivation = source_item.get("source_derivation") if isinstance(source_item.get("source_derivation"), dict) else {}
    password = str(derivation.get("zip_password") or "")
    return password or None


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if str(value)))


def _run_root(output: Path) -> Path:
    return output.parents[1] if output.parent.name == "datasets" and len(output.parents) > 1 else output.parent


def _seed(value: str) -> int:
    if str(value or "").lower() == "random":
        return random.randrange(1, 2**31 - 1)
    return int(value or 20260518)


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)[:160] or "field"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build real ZIP multi-field damage rows through the main analysis/extraction/verification pipeline.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--graph-output", default="")
    parser.add_argument("--failure-output", default="")
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--per-combo-report-output", default="")
    parser.add_argument("--workspace", default="")
    parser.add_argument("--samples-per-size", type=int, default=60)
    parser.add_argument("--combo-sizes", default="2,3,4")
    parser.add_argument("--fields", default="")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--seed", default="20260518")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
