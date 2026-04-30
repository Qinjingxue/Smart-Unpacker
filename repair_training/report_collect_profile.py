from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    events = _load_events(Path(args.input))
    report = _build_report(events, int(args.top or 20))
    output = Path(args.output) if args.output else None
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    print(text)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize collect_repair_plan_data.py debug/profile events.")
    parser.add_argument("--input", required=True, help="Collector debug-events JSONL path.")
    parser.add_argument("--output", default="", help="Optional JSON report path.")
    parser.add_argument("--top", type=int, default=20, help="Number of slow samples/timeouts to include.")
    return parser


def _load_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise SystemExit(f"profile events file does not exist: {path}")
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            if isinstance(item, dict):
                rows.append(item)
    return rows


def _build_report(events: list[dict[str, Any]], top: int) -> dict[str, Any]:
    samples: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for event in events:
        samples[str(event.get("sample_id") or "")].append(event)

    phase_stats: dict[str, list[float]] = collections.defaultdict(list)
    format_stats: dict[str, dict[str, Any]] = collections.defaultdict(lambda: {"samples": 0, "timeouts": 0, "elapsed_seconds": 0.0})
    slow_samples: list[dict[str, Any]] = []
    timeout_samples: list[dict[str, Any]] = []

    for sample_id, sample_events in samples.items():
        end = next((event for event in reversed(sample_events) if event.get("event") == "sample_end"), None)
        timeout = next((event for event in sample_events if event.get("event") == "sample_timeout"), None)
        fmt = str((end or timeout or sample_events[-1]).get("material_format") or (end or timeout or sample_events[-1]).get("format") or "")
        if end:
            elapsed = float(end.get("elapsed_seconds") or 0.0)
            format_stats[fmt]["samples"] += 1
            format_stats[fmt]["elapsed_seconds"] += elapsed
            slow_samples.append({
                "sample_id": sample_id,
                "format": fmt,
                "elapsed_seconds": elapsed,
                "status": end.get("status"),
                "source_archive_name": end.get("source_archive_name"),
                "damaged_file_name": end.get("damaged_file_name"),
            })
        if timeout:
            format_stats[fmt]["timeouts"] += 1
            timeout_samples.append({
                "sample_id": sample_id,
                "format": fmt,
                "elapsed_seconds": timeout.get("elapsed_seconds"),
                "timeout_seconds": timeout.get("timeout_seconds"),
                "last_phase": _last_phase(sample_events),
                "budget": _last_budget(sample_events),
            })
        for event in sample_events:
            if event.get("event") == "phase":
                phase_stats[str(event.get("phase") or "")].append(float(event.get("elapsed_seconds") or 0.0))

    return {
        "event_count": len(events),
        "sample_count": len([events for events in samples.values() if any(event.get("event") == "sample_end" for event in events)]),
        "timeout_count": len(timeout_samples),
        "phase_stats": {
            phase: {
                "count": len(values),
                "total_seconds": round(sum(values), 3),
                "avg_seconds": round(sum(values) / len(values), 3) if values else 0.0,
                "max_seconds": round(max(values), 3) if values else 0.0,
            }
            for phase, values in sorted(phase_stats.items(), key=lambda item: -sum(item[1]))
        },
        "format_stats": {
            fmt: {
                "samples": values["samples"],
                "timeouts": values["timeouts"],
                "elapsed_seconds": round(values["elapsed_seconds"], 3),
                "avg_seconds": round(values["elapsed_seconds"] / values["samples"], 3) if values["samples"] else 0.0,
            }
            for fmt, values in sorted(format_stats.items(), key=lambda item: -item[1]["elapsed_seconds"])
        },
        "slow_samples": sorted(slow_samples, key=lambda item: float(item.get("elapsed_seconds") or 0.0), reverse=True)[:top],
        "timeout_samples": timeout_samples[:top],
    }


def _last_phase(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in reversed(events):
        if event.get("event") == "phase":
            return {
                "phase": event.get("phase"),
                "elapsed_seconds": event.get("elapsed_seconds"),
                "round": event.get("round"),
                "candidate_count": event.get("candidate_count"),
                "accepted_count": event.get("accepted_count"),
                "logged_count": event.get("logged_count"),
            }
    return None


def _last_budget(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in reversed(events):
        budget = event.get("budget")
        if isinstance(budget, dict):
            return budget
    return None


if __name__ == "__main__":
    raise SystemExit(main())
