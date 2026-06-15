from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any

from repair_training.core.datasets import read_jsonl, write_json, write_jsonl
from sunpack.model_runtime.diagnosis.root_cases import ROOT_CASES, canonical_root_case


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    rows = _load_inputs([Path(item) for item in args.inputs])
    excluded = _load_excluded_sample_ids([Path(item) for item in args.exclude_sample_ids_from])
    selected, summary = build_balanced_rows(
        rows,
        target_per_root=int(args.target_per_root),
        clean_limit=int(args.clean_limit),
        max_rows=int(args.max_rows),
        seed=int(args.seed),
        excluded_sample_ids=excluded,
    )
    output = Path(args.output)
    write_jsonl(output, selected)
    summary_path = Path(args.summary_output) if args.summary_output else output.with_name(f"{output.stem}_summary.json")
    write_json(summary_path, summary)
    print(json.dumps({"output": str(output), "summary": str(summary_path), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def build_balanced_rows(
    rows: list[dict[str, Any]],
    *,
    target_per_root: int,
    clean_limit: int,
    max_rows: int,
    seed: int,
    excluded_sample_ids: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rng = random.Random(seed)
    excluded = excluded_sample_ids or set()
    clean_rows: list[dict[str, Any]] = []
    labeled_rows: list[dict[str, Any]] = []
    by_root: dict[str, list[dict[str, Any]]] = {root: [] for root in ROOT_CASES}
    seen_input_ids: set[str] = set()
    duplicate_input_rows = 0
    for row in rows:
        sample_id = str(row.get("sample_id") or "")
        if sample_id and sample_id in excluded:
            continue
        input_key = sample_id or json.dumps(row.get("source") or {}, sort_keys=True)
        if input_key in seen_input_ids:
            duplicate_input_rows += 1
            continue
        seen_input_ids.add(input_key)
        roots = _root_labels(row)
        if not roots:
            if _is_clean(row):
                clean_rows.append(row)
            continue
        labeled_rows.append(row)
        for root in roots:
            by_root.setdefault(root, []).append(row)

    selected: list[dict[str, Any]] = []
    exposure = Counter()
    emitted = 0
    for root in ROOT_CASES:
        candidates = list(by_root.get(root) or [])
        if not candidates:
            continue
        rng.shuffle(candidates)
        # Reuse rows when the real corpus does not have enough unique examples.
        for index in range(max(0, target_per_root)):
            row = candidates[index % len(candidates)]
            selected.append(_training_clone(row, emitted=emitted, root=root, repeat_index=index))
            emitted += 1
            for label in _root_labels(row):
                exposure[label] += 1

    rng.shuffle(clean_rows)
    if clean_limit > 0 and clean_rows:
        for index in range(clean_limit):
            selected.append(_clean_training_clone(clean_rows[index % len(clean_rows)], repeat_index=index))
    elif clean_limit < 0:
        selected.extend(clean_rows)

    if max_rows > 0 and len(selected) > max_rows:
        # Keep clean rows, then sample labeled rows by inverse current exposure.
        clean_selected = [row for row in selected if not _root_labels(row)]
        labeled_selected = [row for row in selected if _root_labels(row)]
        target_labeled = max(0, max_rows - len(clean_selected))
        weights = []
        root_counts = _root_counts(labeled_selected)
        for row in labeled_selected:
            roots = _root_labels(row)
            rarity = sum(1.0 / max(1, root_counts[root]) for root in roots) / max(1, len(roots))
            weights.append(rarity)
        labeled_selected = _weighted_sample_without_replacement(labeled_selected, weights, target_labeled, rng)
        selected = [*labeled_selected, *clean_selected[:max_rows - len(labeled_selected)]]

    rng.shuffle(selected)
    summary = {
        "schema": "balanced_diagnosis_gnn_rows_v1",
        "input_rows": len(rows),
        "duplicate_input_rows": duplicate_input_rows,
        "excluded_sample_ids": len(excluded),
        "rows": len(selected),
        "clean_rows": sum(1 for row in selected if not _root_labels(row)),
        "target_per_root": target_per_root,
        "root_counts": dict(sorted(_root_counts(selected).items())),
        "root_unique_source_counts": {
            root: len({_selection_key(row) for row in by_root.get(root, [])})
            for root in ROOT_CASES
        },
    }
    return selected, summary


def _load_inputs(paths: list[Path]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for path in paths:
        output.extend(read_jsonl(path))
    return output


def _load_excluded_sample_ids(paths: list[Path]) -> set[str]:
    output: set[str] = set()
    for path in paths:
        for row in read_jsonl(path):
            sample_id = str(row.get("sample_id") or "")
            if sample_id:
                output.add(sample_id)
    return output


def _root_labels(row: dict[str, Any]) -> list[str]:
    labels = row.get("labels") if isinstance(row.get("labels"), dict) else {}
    root = labels.get("root_case") if isinstance(labels.get("root_case"), dict) else {}
    raw = root.get("labels") or root.get("root_case_labels") or []
    roots = []
    for item in raw:
        root_name = canonical_root_case(str(item or ""))
        if root_name:
            roots.append(root_name)
    return sorted(set(roots))


def _is_clean(row: dict[str, Any]) -> bool:
    labels = row.get("labels") if isinstance(row.get("labels"), dict) else {}
    auxiliary = labels.get("auxiliary") if isinstance(labels.get("auxiliary"), dict) else {}
    return bool(auxiliary.get("clean"))


def _selection_key(row: dict[str, Any]) -> str:
    return str(row.get("sample_id") or json.dumps(row.get("source") or {}, sort_keys=True))


def _training_clone(row: dict[str, Any], *, emitted: int, root: str, repeat_index: int) -> dict[str, Any]:
    updated = dict(row)
    original = str(updated.get("sample_id") or f"row_{emitted:08d}")
    updated["sample_id"] = f"{original}::balanced::{root}::{repeat_index:04d}"
    source = dict(updated.get("source") or {})
    source["original_sample_id"] = original
    source["balanced_training_root"] = root
    source["balanced_repeat_index"] = repeat_index
    updated["source"] = source
    return updated


def _clean_training_clone(row: dict[str, Any], *, repeat_index: int) -> dict[str, Any]:
    updated = dict(row)
    original = str(updated.get("sample_id") or f"clean_{repeat_index:08d}")
    updated["sample_id"] = f"{original}::clean_balance::{repeat_index:04d}"
    source = dict(updated.get("source") or {})
    source["original_sample_id"] = original
    source["balanced_clean_repeat_index"] = repeat_index
    updated["source"] = source
    return updated


def _root_counts(rows: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in rows:
        counts.update(_root_labels(row))
    return counts


def _weighted_sample_without_replacement(items: list[dict[str, Any]], weights: list[float], count: int, rng: random.Random) -> list[dict[str, Any]]:
    if count >= len(items):
        return list(items)
    remaining = list(zip(items, weights))
    output = []
    while remaining and len(output) < count:
        total = sum(max(0.0, weight) for _, weight in remaining)
        if total <= 0:
            index = rng.randrange(len(remaining))
        else:
            pick = rng.random() * total
            index = 0
            running = 0.0
            for candidate_index, (_, weight) in enumerate(remaining):
                running += max(0.0, weight)
                if running >= pick:
                    index = candidate_index
                    break
        item, _ = remaining.pop(index)
        output.append(item)
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build root-balanced DiagnosisGNN graph rows without format-specific rules.")
    parser.add_argument("--inputs", nargs="+", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--exclude-sample-ids-from", nargs="*", default=[])
    parser.add_argument("--target-per-root", type=int, default=260)
    parser.add_argument("--clean-limit", type=int, default=300)
    parser.add_argument("--max-rows", type=int, default=0)
    parser.add_argument("--seed", type=int, default=20260523)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
