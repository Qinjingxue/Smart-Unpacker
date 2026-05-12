from __future__ import annotations

import argparse
import json
import struct
import zipfile
from pathlib import Path
from typing import Any


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bucket remaining zip_data_descriptor_cd_conflict oracle gaps by entry-level differences.")
    parser.add_argument("--manifest", default="repair_training/datasets/repair_plan_ltr_success_zip_v31.jsonl")
    parser.add_argument("--output", default="repair_training/datasets/descriptor_cd_conflict_diff.json")
    parser.add_argument("--profile", default="zip_data_descriptor_cd_conflict")
    args = parser.parse_args(argv)
    rows = _best_rows(Path(args.manifest), args.profile)
    samples = [_sample_diff(row) for row in rows if int(row.get("label", 0) or 0) < 3]
    buckets: dict[str, int] = {}
    for sample in samples:
        for bucket in sample.get("buckets", []) or ["unknown"]:
            buckets[bucket] = int(buckets.get(bucket, 0) or 0) + 1
    payload = {"profile": args.profile, "samples": samples, "descriptor_cd_conflict_diff_buckets": dict(sorted(buckets.items()))}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "samples": len(samples), "buckets": payload["descriptor_cd_conflict_diff_buckets"]}, ensure_ascii=False))
    return 0


def _best_rows(path: Path, profile: str) -> list[dict[str, Any]]:
    best: dict[str, tuple[tuple[int, float], dict[str, Any]]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            sample_id = str(row.get("episode_id") or row.get("sample_id") or "")
            if profile not in sample_id and profile != _profile_from_row(row):
                continue
            details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
            key = (int(row.get("label", 0) or 0), float(details.get("completeness", row.get("best_recovery_ratio", 0.0)) or 0.0))
            if sample_id not in best or key > best[sample_id][0]:
                best[sample_id] = (key, row)
    return [item[1] for item in best.values()]


def _profile_from_row(row: dict[str, Any]) -> str:
    state = ((row.get("stable_features") or {}).get("state") or {}) if isinstance(row.get("stable_features"), dict) else {}
    return str(state.get("damage_profile") or row.get("damage_profile") or "")


def _sample_diff(row: dict[str, Any]) -> dict[str, Any]:
    sample_id = str(row.get("episode_id") or row.get("sample_id") or "")
    source_path = _source_path(row)
    oracle = _oracle(row)
    buckets: set[str] = set()
    entries = []
    if source_path and Path(source_path).is_file():
        metadata = _zip_metadata(Path(source_path))
        oracle_entries = oracle.get("expected_files") if isinstance(oracle.get("expected_files"), dict) else {}
        for name, expected in oracle_entries.items():
            actual = metadata.get(name)
            if actual is None:
                buckets.add("missing_entry")
                entries.append({"name": name, "status": "missing_entry"})
                continue
            diff = {"name": name, "status": "present", "fields": []}
            for field in ("crc", "compressed_size", "uncompressed_size", "local_header_offset"):
                expected_value = expected.get("crc32" if field == "crc" else field)
                actual_value = actual.get(field)
                if expected_value is not None and actual_value is not None and int(expected_value) != int(actual_value):
                    diff["fields"].append(field)
                    buckets.add(f"{field}_mismatch")
            if actual.get("bit3_descriptor"):
                buckets.add("bit3_descriptor_present")
            entries.append(diff)
    if not buckets:
        buckets.add("payload_hash_or_oracle_only")
    return {"sample_id": sample_id, "source_path": source_path, "buckets": sorted(buckets), "entries": entries[:50]}


def _source_path(row: dict[str, Any]) -> str:
    for key in ("repaired_input", "source_input"):
        raw = row.get(key)
        if isinstance(raw, dict) and raw.get("path"):
            return str(raw.get("path"))
    details = row.get("label_details") if isinstance(row.get("label_details"), dict) else {}
    after = details.get("after_state") if isinstance(details.get("after_state"), dict) else {}
    return str(after.get("source_path") or "")


def _oracle(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("oracle")
    return raw if isinstance(raw, dict) else {}


def _zip_metadata(path: Path) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                output[info.filename] = {
                    "crc": info.CRC,
                    "compressed_size": info.compress_size,
                    "uncompressed_size": info.file_size,
                    "local_header_offset": info.header_offset,
                    "bit3_descriptor": bool(info.flag_bits & 0x08),
                }
    except Exception:
        output["_archive_error"] = {"error": "unreadable_zip"}
    return output


if __name__ == "__main__":
    raise SystemExit(main())
