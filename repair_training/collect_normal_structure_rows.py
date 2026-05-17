from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from repair_training.core.datasets import sha256_file, write_json, write_jsonl
from repair_training.core.plugin import normalize_format_name
from sunpack.detection.pipeline.processors.modules.format_structure.zip_structure_graph import inspect_zip_structure_graph


SCHEMA_VERSION = 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    if fmt != "zip":
        raise SystemExit("collect_normal_structure_rows currently supports --format zip only")
    output = Path(args.output)
    rows = collect_normal_structure_rows(
        material_root=Path(args.material_root),
        limit=max(0, int(args.limit or 0)),
        seed=int(args.seed or 20260516),
        max_entries=max(1, int(args.max_entries or 128)),
    )
    write_jsonl(output, rows)
    summary = _summary(rows)
    summary_path = Path(args.summary_output) if args.summary_output else output.with_name("normal_structure_row_summary.json")
    write_json(summary_path, summary)
    print(json.dumps({"output": str(output), "summary": str(summary_path), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def collect_normal_structure_rows(
    *,
    material_root: str | Path,
    limit: int = 0,
    seed: int = 20260516,
    max_entries: int = 128,
) -> list[dict[str, Any]]:
    sources = _zip_sources(Path(material_root))
    if limit:
        sources = sources[:limit]
    rows: list[dict[str, Any]] = []
    for index, path in enumerate(sources):
        graph = inspect_zip_structure_graph(str(path), max_entries=max_entries)
        source_identity = {
            "source_archive_id": path.stem,
            "source_path": str(path),
            "clean_sha256": _sha256(path),
        }
        rows.append({
            "schema_version": SCHEMA_VERSION,
            "row_type": "normal_structure_supervised",
            "sample_id": f"clean:{index:06d}",
            "format": "zip",
            "source_identity": source_identity,
            "state_digest": source_identity["clean_sha256"],
            "knowledge_payload": {
                "format": {
                    "zip": {
                        "structure": {
                            "graph": graph,
                        }
                    }
                },
                "source": {
                    "input": {
                        "kind": "path",
                        "format_hint": "zip",
                    }
                },
            },
            "normal_label": 1,
        })
    return rows


def rows_from_graph(
    graph: dict[str, Any],
    *,
    sample_id: str,
    source_identity: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    return [{
        "schema_version": SCHEMA_VERSION,
        "row_type": "normal_structure_supervised",
        "sample_id": sample_id,
        "format": "zip",
        "source_identity": dict(source_identity or {}),
        "knowledge_payload": {"format": {"zip": {"structure": {"graph": graph}}}},
        "normal_label": 1,
    }]


def _zip_sources(material_root: Path) -> list[Path]:
    root = material_root / "zip" if (material_root / "zip").is_dir() else material_root
    return sorted(
        path
        for path in root.rglob("*.zip")
        if path.is_file() and "damaged" not in {part.lower() for part in path.parts}
    )


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels = Counter(int(row.get("normal_label") or 0) for row in rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "rows": len(rows),
        "normal_rows": int(labels.get(1, 0)),
        "anomaly_rows": int(labels.get(0, 0)),
    }


def _sha256(path: Path) -> str:
    try:
        return sha256_file(path)
    except Exception:
        return ""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect self-supervised ZIP normal-structure query rows from clean material.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--material-root", default=str(Path("repair_training") / "material"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--seed", type=int, default=20260516)
    parser.add_argument("--max-entries", type=int, default=128)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
