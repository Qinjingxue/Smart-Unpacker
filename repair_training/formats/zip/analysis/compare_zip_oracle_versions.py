from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


FOCUS_PROFILES = (
    "zip_non_utf8_filename_directory_rebuild",
    "zip_zip64_extra_size_mismatch",
    "zip_sfx_cd_damage",
    "zip_sfx_payload_damage",
    "zip_duplicate_entry_crc_conflict",
    "zip_split_missing_middle_volume",
    "zip_data_descriptor_cd_conflict",
    "zip_data_descriptor_payload_bad",
    "zip_split_tail_volume_truncated",
    "zip_comment_overlap_eocd_shifted",
    "zip_zip64_eocd_locator_bad",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare ZIP repair training oracle recovery across dataset versions.")
    parser.add_argument("--datasets-dir", default="repair_training/datasets")
    parser.add_argument("--versions", default="v19,v24,v25")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    root = Path(args.datasets_dir)
    versions = [item.strip() for item in args.versions.split(",") if item.strip()]
    report = {"summary": {}, "focus": {}}
    analyses = {version: _analyze_version(root, version) for version in versions}

    for version, analysis in analyses.items():
        total = Counter()
        for counts in analysis["profile_counts"].values():
            total.update(counts)
        report["summary"][version] = {
            "samples": len(analysis["samples"]),
            "labels": dict(sorted(total.items())),
        }

    for profile in FOCUS_PROFILES:
        report["focus"][profile] = {}
        for version, analysis in analyses.items():
            count, total = analysis["profile_completeness"].get(profile, [0, 0.0])
            report["focus"][profile][version] = {
                "label_counts": dict(sorted(analysis["profile_counts"].get(profile, {}).items())),
                "avg_completeness": (total / count) if count else None,
            }

    output = Path(args.output) if args.output else root / f"oracle_recovery_compare_zip_{'_'.join(versions)}.json"
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2, sort_keys=True))
    print(f"wrote {output}")


def _analyze_version(root: Path, version: str) -> dict[str, Any]:
    best_by_sample: dict[str, dict[str, Any]] = {}
    for kind in ("success", "failure"):
        path = root / f"repair_plan_ltr_{kind}_zip_{version}.jsonl"
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                sample = str(row.get("episode_id") or row.get("sample_id") or "")
                if not sample:
                    continue
                label = int(row.get("label") or 0)
                completeness = _completeness(row)
                current = best_by_sample.get(sample)
                if current is None or (label, completeness) > (current["label"], current["completeness"]):
                    best_by_sample[sample] = {
                        "profile": _profile(row),
                        "label": label,
                        "completeness": completeness,
                    }

    profile_counts: defaultdict[str, Counter] = defaultdict(Counter)
    profile_completeness: defaultdict[str, list[float]] = defaultdict(lambda: [0, 0.0])
    for item in best_by_sample.values():
        profile = str(item["profile"])
        label = int(item["label"])
        profile_counts[profile][label] += 1
        profile_completeness[profile][0] += 1
        profile_completeness[profile][1] += float(item["completeness"])
    return {
        "samples": best_by_sample,
        "profile_counts": profile_counts,
        "profile_completeness": profile_completeness,
    }


def _profile(row: dict[str, Any]) -> str:
    name = str(row.get("damaged_file_name") or row.get("episode_id") or "")
    for profile in FOCUS_PROFILES:
        if profile in name:
            return profile
    return str(row.get("zip_variant") or "other")


def _completeness(row: dict[str, Any]) -> float:
    details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
    for key in ("completeness", "terminal_recovery_ratio"):
        if details.get(key) is not None:
            return float(details.get(key) or 0.0)
    return float(row.get("terminal_recovery_ratio") or 0.0)


if __name__ == "__main__":
    main()
