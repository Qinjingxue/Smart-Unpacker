from __future__ import annotations

import argparse
import statistics
from pathlib import Path

from sunpack_native import probe_volume_anchors, reader_cache_stats

from benchmarks.harness import (
    BenchmarkWorkspace,
    measure,
    metrics_delta,
    render_report,
    report_from_payload,
)


SCENARIO = "reader.volume-anchor"
ORDINARY_READ_LIMIT = 512 + 65_557


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark the bounded native Relations volume-anchor fast path."
    )
    parser.add_argument("--files", type=int, default=128)
    parser.add_argument("--logical-mib", type=int, default=64)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--keep-workdir", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if min(args.files, args.logical_mib, args.rounds) < 1:
        raise SystemExit("files, logical-mib, and rounds must be positive")

    with BenchmarkWorkspace(
        SCENARIO,
        results_root=args.results_root,
        keep_workdir=args.keep_workdir,
    ) as workspace:
        paths = _build_sparse_corpus(workspace.corpus, args.files, args.logical_mib)
        before = dict(reader_cache_stats())

        def invoke() -> list[dict]:
            rows = [dict(row) for row in probe_volume_anchors(paths)]
            assert len(rows) == len(paths)
            assert all(int(row["bytes_read"]) <= ORDINARY_READ_LIMIT for row in rows)
            return rows

        measured = measure(invoke, runs=args.rounds, warmups=1)
        after = dict(reader_cache_stats())
        samples = [
            {
                "round": row.iteration + 1,
                "wall_ms": round(row.wall_ms, 3),
                "cpu_ms": round(row.cpu_ms, 3),
                "files_per_second": round(args.files / (row.wall_ms / 1000), 1),
                "bytes_read": sum(int(item["bytes_read"]) for item in row.value),
            }
            for row in measured
        ]
        report = report_from_payload(
            SCENARIO,
            {
                "parameters": {
                    "files": args.files,
                    "logical_mib_per_file": args.logical_mib,
                    "rounds": args.rounds,
                    "ordinary_read_limit_per_file": ORDINARY_READ_LIMIT,
                },
                "samples": samples,
                "summary": {
                    "median_wall_ms": round(
                        statistics.median(row.wall_ms for row in measured), 3
                    ),
                    "median_files_per_second": round(
                        statistics.median(row["files_per_second"] for row in samples), 1
                    ),
                    "max_bytes_read_per_file": max(
                        int(item["bytes_read"])
                        for measurement in measured
                        for item in measurement.value
                    ),
                    "reader_delta": metrics_delta(before, after),
                },
            },
        )
        rendered = render_report(report)
        workspace.write_result_text("report.json", rendered)
        print(rendered)


def _build_sparse_corpus(root: Path, count: int, logical_mib: int) -> list[str]:
    size = logical_mib * 1024 * 1024
    paths = []
    for index in range(count):
        path = root / f"opaque-{index:05d}.part"
        with path.open("wb") as stream:
            stream.truncate(size)
        paths.append(str(path))
    return paths


if __name__ == "__main__":
    main()
