from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from repair_training.training_corruption import (
    MATERIAL_FORMAT_DIRS,
    build_corpus_corruption_case,
    detect_archive_format,
    material_dir_to_format,
)


DEFAULT_MATERIAL_ROOT = Path("repair_training") / "material"
DEFAULT_OUTPUT_DIR = Path(".sunpack") / "corpus"
DEFAULT_MANIFEST = DEFAULT_OUTPUT_DIR / "repair_plan_manifest.jsonl"
PROFILE_LAYERS = (
    ("structural", 0.30, ("structural_boundary", "structural_header_tail", "structural_footer_tail")),
    ("structural_directory", 0.30, (
        "zip_drop_central_directory_keep_local_headers",
        "zip_eocd_cd_half_damaged",
        "zip_directory_only_bad_payload",
        "zip_wrong_local_offset_extracts_valid_other_entry",
        "zip_rebuild_directory_keeps_bad_payload",
        "zip_quarantine_keeps_corrupted_entry",
        "zip_cd_offset_near_valid_wrong_entry",
        "zip_eocd_counts_wrong_but_cd_readable",
        "zip_local_header_crc_wrong_cd_correct",
        "zip_cd_crc_wrong_local_payload_correct",
        "zip_comment_overlap_eocd_shifted",
        "zip_duplicate_entries_conflicting_crc",
        "zip_data_descriptor_conflict",
        "zip_partial_cd_rebuild_then_payload_mismatch",
        "zip_sfx_cd_damage",
        "zip_data_descriptor_cd_conflict",
        "zip_zip64_eocd_locator_bad",
        "zip_zip64_extra_size_mismatch",
        "zip_duplicate_entry_crc_conflict",
        "zip_non_utf8_filename_directory_rebuild",
        "zip_extra_field_length_bad",
        "zip_mixed_method_one_entry_bad",
        "structural_directory",
        "structural_metadata",
        "structural_index",
    )),
    ("partial_recoverable", 0.25, (
        "zip_single_entry_payload_damage",
        "zip_drop_central_directory_keep_local_headers",
        "zip_split_missing_middle_volume",
        "zip_split_tail_volume_truncated",
        "tar_truncate_last_member",
        "tar_damage_one_member_payload",
        "seven_zip_non_solid_one_file_damage",
        "rar_non_solid_one_file_damage",
    )),
    ("hard_negative", 0.15, (
        "zip_all_entry_payload_damage_with_directory",
        "zip_wrong_offset_content_overlap",
        "hard_negative_payload",
        "hard_negative_block_tail",
        "hard_negative_multi",
    )),
    ("two_step_repair", 0.20, (
        "zip_two_step_boundary_then_cd_rebuild",
        "zip_two_step_comment_fix_then_eocd_repair",
        "zip_two_step_local_header_then_cd_offset",
        "zip_two_step_drop_cd_with_eocd_noise",
    )),
    ("deceptive_hard_negative", 0.30, (
        "zip_rebuild_directory_keeps_bad_payload",
        "zip_wrong_local_offset_extracts_valid_other_entry",
        "zip_directory_only_bad_payload",
        "zip_quarantine_keeps_corrupted_entry",
        "zip_eocd_cd_half_damaged",
        "zip_crc_repair_masks_payload_mismatch",
        "zip_partial_recovery_wrong_hash_same_name",
        "zip_sfx_payload_damage",
        "zip_sfx_split_missing_volume",
        "zip_data_descriptor_payload_bad",
    )),
)
DEFAULT_LAYER_BUDGET = (
    ("structural", 2),
    ("structural_directory", 2),
    ("partial_recoverable", 3),
    ("hard_negative", 3),
)
ZIP_LAYER_BUDGET = (
    ("structural", 1),
    ("structural_directory", 3),
    ("partial_recoverable", 1),
    ("hard_negative", 2),
    ("two_step_repair", 5),
    ("deceptive_hard_negative", 3),
)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    material_root = Path(args.material_root)
    if args.init_material:
        _init_material(material_root)
        print(json.dumps({"material_root": str(material_root), "format_dirs": list(MATERIAL_FORMAT_DIRS)}, ensure_ascii=False, sort_keys=True))
        return 0
    _init_material(material_root)
    if args.input_dir:
        return _legacy_build(args)
    return _material_build(args, material_root)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build multi-damage repair-plan material from clean archives.")
    parser.add_argument("--init-material", action="store_true", help="Create repair_training/material format directories and exit.")
    parser.add_argument("--material-root", default=str(DEFAULT_MATERIAL_ROOT), help="Root containing <format>/<sample_id> material folders.")
    parser.add_argument("--per-sample", type=int, default=10, help="Damaged variants per source archive inside each material sample folder.")
    parser.add_argument("--seed", default="random", help="Random seed. Use 'random' for a fresh seed each run.")
    parser.add_argument("--formats", default="", help="Optional comma-separated material format directory allowlist.")
    parser.add_argument("--sample", action="append", default=[], help="Optional sample folder name filter. Repeatable.")
    parser.add_argument("--no-pretty", action="store_false", dest="pretty", help="Only write JSONL manifests.")
    parser.set_defaults(pretty=True)

    parser.add_argument("--input-dir", default="", help="Legacy: directory of clean archives.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Legacy output directory.")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="Legacy aggregate manifest JSONL path.")
    parser.add_argument("--per-source", type=int, default=0, help="Legacy variants per source; defaults to --per-sample.")
    parser.add_argument("--append", action="store_true", help="Legacy append to aggregate manifest.")
    return parser


def _material_build(args: argparse.Namespace, material_root: Path) -> int:
    base_seed = _resolve_seed(args.seed)
    rng = random.Random(base_seed)
    formats = _format_filter(args.formats)
    sample_filter = set(args.sample or [])
    summary = {"material_root": str(material_root), "seed": base_seed, "organized": 0, "samples": 0, "sources": 0, "generated": 0, "skipped": 0}
    for format_dir in _format_dirs(material_root, formats):
        fmt = material_dir_to_format(format_dir.name)
        if fmt is None:
            continue
        summary["organized"] += _organize_root_sources(format_dir, fmt, sample_filter)
        for sample_dir in sorted(item for item in format_dir.iterdir() if item.is_dir()):
            if sample_dir.name == "damaged":
                continue
            if sample_filter and sample_dir.name not in sample_filter:
                continue
            sample_sources = _sample_sources(sample_dir, fmt)
            if not sample_sources:
                continue
            summary["samples"] += 1
            summary["sources"] += len(sample_sources)
            records = []
            _clear_generated_material(sample_dir)
            damaged_root = sample_dir / "damaged"
            damaged_root.mkdir(parents=True, exist_ok=True)
            for source_index, source in enumerate(sample_sources):
                source_archive_id = _source_archive_id(source)
                source_derivation = _load_source_derivation(source)
                zip_password = str(source_derivation.get("zip_password") or "") if source_derivation else ""
                layer_plan = _damage_layer_plan(rng, fmt, max(0, int(args.per_sample)))
                for variant_index, (requested_layer, layer, layer_weight, profile, skip_reason) in enumerate(layer_plan):
                    profile, structure_targeted_profile = _zip_structure_target_profile(
                        rng,
                        fmt,
                        source_derivation,
                        layer,
                        profile,
                    )
                    variant_seed = rng.randrange(1, 2**31 - 1)
                    case_root = damaged_root / source.stem / f"v{variant_index:03d}"
                    damage_json_path = case_root / f"{source.stem}_{variant_index:03d}.damage.json"
                    try:
                        case = build_corpus_corruption_case(
                            case_root,
                            source_path=source,
                            fmt=fmt,
                            seed=variant_seed + source_index,
                            variant_index=variant_index,
                            damage_profile=profile,
                            source_derivation=source_derivation,
                            password=zip_password or None,
                        )
                        record = case.corpus_manifest_record(
                            source_archive_id=source_archive_id,
                            source_path=str(source),
                            damage_profile=profile,
                            variant_index=variant_index,
                            material_format=format_dir.name,
                            material_sample_id=sample_dir.name,
                            damage_json_path=str(damage_json_path),
                        )
                        if zip_password and not record.get("password"):
                            record["password"] = zip_password
                        record["damage_layer"] = layer
                        record["requested_damage_layer"] = requested_layer
                        record["actual_damage_layer"] = layer
                        record["damage_layer_weight"] = layer_weight
                        record["structure_targeted_profile"] = bool(structure_targeted_profile)
                        if skip_reason:
                            record["skip_reason"] = skip_reason
                        if source_derivation:
                            record["source_derivation"] = source_derivation
                            _copy_zip_derivation_fields(record, source_derivation)
                        damage_json_path.parent.mkdir(parents=True, exist_ok=True)
                        damage_json_path.write_text(json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
                        records.append(record)
                        summary["generated"] += 1
                    except Exception as exc:
                        records.append(_skipped_record(source, fmt, source_archive_id, variant_index, profile, exc, format_dir.name, sample_dir.name, damage_layer=layer, damage_layer_weight=layer_weight, requested_damage_layer=requested_layer, actual_damage_layer=layer, skip_reason=skip_reason))
                        summary["skipped"] += 1
            _write_sample_manifest(sample_dir, records, bool(args.pretty))
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _legacy_build(args: argparse.Namespace) -> int:
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    damaged_dir = output_dir / "damaged"
    manifest_path = Path(args.manifest or output_dir / "repair_plan_manifest.jsonl")
    damaged_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    formats = _format_filter(args.formats)
    seed = _resolve_seed(args.seed)
    rng = random.Random(seed)
    per_source = int(args.per_source or args.per_sample)
    records: list[dict[str, Any]] = []
    sources = _source_archives(input_dir, formats)
    for source_index, source in enumerate(sources):
        fmt = detect_archive_format(source)
        if fmt is None:
            continue
        source_archive_id = _source_archive_id(source)
        layer_plan = _damage_layer_plan(rng, fmt, max(0, per_source))
        for variant_index, (requested_layer, layer, layer_weight, profile, skip_reason) in enumerate(layer_plan):
            case_root = damaged_dir / source_archive_id / f"v{variant_index:03d}"
            try:
                case = build_corpus_corruption_case(
                    case_root,
                    source_path=source,
                    fmt=fmt,
                    seed=rng.randrange(1, 2**31 - 1) + source_index,
                    variant_index=variant_index,
                    damage_profile=profile,
                )
            except Exception as exc:
                records.append(_skipped_record(source, fmt, source_archive_id, variant_index, profile, exc, damage_layer=layer, damage_layer_weight=layer_weight, requested_damage_layer=requested_layer, actual_damage_layer=layer, skip_reason=skip_reason))
                continue
            record = case.corpus_manifest_record(source_archive_id=source_archive_id, source_path=str(source), damage_profile=profile, variant_index=variant_index)
            record["damage_layer"] = layer
            record["requested_damage_layer"] = requested_layer
            record["actual_damage_layer"] = layer
            record["damage_layer_weight"] = layer_weight
            if skip_reason:
                record["skip_reason"] = skip_reason
            records.append(record)
    mode = "a" if args.append else "w"
    with manifest_path.open(mode, encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
    if args.pretty:
        _pretty_path(manifest_path).write_text(json.dumps(records, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
    print(json.dumps({"sources": len(sources), "records": len(records), "generated": sum(1 for item in records if item.get("damaged_input")), "seed": seed, "manifest": str(manifest_path)}, ensure_ascii=False, sort_keys=True))
    return 0


def _init_material(material_root: Path) -> None:
    material_root.mkdir(parents=True, exist_ok=True)
    for name in MATERIAL_FORMAT_DIRS:
        (material_root / name).mkdir(parents=True, exist_ok=True)


def _clear_generated_material(sample_dir: Path) -> None:
    damaged = (sample_dir / "damaged").resolve()
    sample = sample_dir.resolve()
    if damaged.exists():
        if sample not in damaged.parents:
            raise RuntimeError(f"refusing to remove generated directory outside sample: {damaged}")
        shutil.rmtree(damaged)
    for name in ("damage_manifest.jsonl", "damage_manifest.pretty.json"):
        target = sample_dir / name
        if target.exists():
            target.unlink()


def _write_sample_manifest(sample_dir: Path, records: list[dict[str, Any]], pretty: bool) -> None:
    manifest = sample_dir / "damage_manifest.jsonl"
    with manifest.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
    if pretty:
        (sample_dir / "damage_manifest.pretty.json").write_text(json.dumps(records, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _format_dirs(material_root: Path, formats: set[str]) -> list[Path]:
    dirs = []
    for name in MATERIAL_FORMAT_DIRS:
        if formats and name not in formats and str(material_dir_to_format(name) or "") not in formats:
            continue
        path = material_root / name
        if path.is_dir():
            dirs.append(path)
    return dirs


def _sample_sources(sample_dir: Path, fmt: str) -> list[Path]:
    output = []
    for path in sorted(sample_dir.iterdir()):
        if not path.is_file():
            continue
        detected = detect_archive_format(path)
        if detected == fmt:
            output.append(path)
    return output


def _zip_structure_target_profile(
    rng: random.Random,
    fmt: str,
    source_derivation: dict[str, Any],
    layer: str,
    fallback_profile: str,
) -> tuple[str, bool]:
    if _normalized_material_format(fmt) != "zip" or not source_derivation:
        return fallback_profile, False
    variant = str(source_derivation.get("zip_variant") or "").lower()
    tags = {str(item).lower() for item in source_derivation.get("zip_container_tags") or []}
    candidates: list[str] = []
    if variant == "encrypted_zipcrypto" or "encrypted" in tags:
        candidates.extend(["zip_encrypted_trailing_junk", "zip_encrypted_payload_bad"])
    if variant in {"sfx_stub", "sfx_split_zip"} or "sfx" in tags:
        candidates.extend(["zip_sfx_cd_damage", "zip_sfx_payload_damage"])
    if variant == "sfx_split_zip":
        candidates.append("zip_sfx_split_missing_volume")
    if variant == "split_zip" or "split" in tags:
        candidates.extend(["zip_split_missing_middle_volume", "zip_split_tail_volume_truncated"])
    if variant == "data_descriptor_bit3" or "data_descriptor" in tags:
        candidates.extend(["zip_data_descriptor_cd_conflict", "zip_data_descriptor_payload_bad"])
    if variant == "long_comment" or "long_comment" in tags or "eocd_comment" in tags:
        candidates.append("zip_comment_overlap_eocd_shifted")
    if variant == "zip64_forced" or "zip64" in tags:
        candidates.extend(["zip_zip64_eocd_locator_bad", "zip_zip64_extra_size_mismatch"])
    if variant == "duplicate_entries" or "duplicate_entries" in tags:
        candidates.append("zip_duplicate_entry_crc_conflict")
    if variant == "non_utf8_names" or "filename_encoding" in tags:
        candidates.append("zip_non_utf8_filename_directory_rebuild")
    if variant in {"mixed_store_deflate"} or "mixed_methods" in tags:
        candidates.append("zip_mixed_method_one_entry_bad")
    if "extra_field" in tags and "zip64" not in tags:
        candidates.append("zip_extra_field_length_bad")
    layer_candidates = [
        item
        for item in candidates
        if _profile_layer_name(item) in {layer, "structural_directory", "partial_recoverable", "deceptive_hard_negative"}
    ]
    choices = layer_candidates or candidates
    if not choices:
        return fallback_profile, False
    return str(rng.choice(choices)), True


def _profile_layer_name(profile: str) -> str:
    text = str(profile or "").lower()
    if "payload_bad" in text or "sfx_payload_damage" in text:
        return "deceptive_hard_negative"
    if "missing" in text or "truncated" in text:
        return "partial_recoverable"
    return "structural_directory"


def _copy_zip_derivation_fields(record: dict[str, Any], source_derivation: dict[str, Any]) -> None:
    for key in ("zip_variant", "zip_container_tags", "zip_structure_features"):
        if key in source_derivation:
            record[key] = source_derivation.get(key)


def _organize_root_sources(format_dir: Path, fmt: str, sample_filter: set[str]) -> int:
    moved = 0
    for path in sorted(format_dir.iterdir()):
        if not path.is_file():
            continue
        if path.name == ".gitkeep":
            continue
        if detect_archive_format(path) != fmt:
            continue
        sample_name = _safe_sample_name(path.stem)
        if sample_filter and sample_name not in sample_filter:
            continue
        sample_dir = _sample_dir_for_root_source(format_dir, sample_name, path.name)
        sample_dir.mkdir(parents=True, exist_ok=True)
        target = sample_dir / path.name
        if target.exists():
            raise RuntimeError(f"refusing to overwrite existing material source: {target}")
        shutil.move(str(path), str(target))
        moved += 1
    return moved


def _sample_dir_for_root_source(format_dir: Path, sample_name: str, filename: str) -> Path:
    candidate = format_dir / sample_name
    if not (candidate / filename).exists():
        return candidate
    index = 2
    while True:
        candidate = format_dir / f"{sample_name}_{index}"
        if not (candidate / filename).exists():
            return candidate
        index += 1


def _safe_sample_name(raw: str) -> str:
    value = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in str(raw or "").strip())
    return value or "sample"


def _source_archives(input_dir: Path, formats: set[str]) -> list[Path]:
    if not input_dir.is_dir():
        raise SystemExit(f"input directory does not exist: {input_dir}")
    output = []
    for path in sorted(input_dir.rglob("*")):
        if not path.is_file():
            continue
        fmt = detect_archive_format(path)
        if fmt is None:
            continue
        if formats and fmt not in formats:
            continue
        output.append(path)
    return output


def _format_filter(raw: str) -> set[str]:
    return {item.strip().lower() for item in str(raw or "").split(",") if item.strip()}


def _resolve_seed(raw: str) -> int:
    if str(raw).strip().lower() in {"", "random", "none"}:
        return random.SystemRandom().randrange(1, 2**31 - 1) ^ int(time.time_ns() & 0x7FFFFFFF)
    return int(raw)


def _choose_damage_profile(rng: random.Random, fmt: str = "") -> tuple[str, float, str]:
    roll = rng.random()
    cumulative = 0.0
    total_weight = sum(max(0.0, float(weight)) for _, weight, _ in PROFILE_LAYERS) or 1.0
    for layer, weight, profiles in PROFILE_LAYERS:
        cumulative += max(0.0, float(weight)) / total_weight
        if roll <= cumulative:
            return _compatible_damage_profile(rng, layer, float(weight), profiles, fmt)
    layer, weight, profiles = PROFILE_LAYERS[-1]
    return _compatible_damage_profile(rng, layer, float(weight), profiles, fmt)


def _compatible_damage_profile(rng: random.Random, layer: str, weight: float, profiles: tuple[str, ...], fmt: str) -> tuple[str, float, str]:
    normalized = _normalized_material_format(fmt)
    if layer == "partial_recoverable" and not _supports_entry_partial(normalized):
        structural = next(item for item in PROFILE_LAYERS if item[0] == "structural")
        return structural[0], float(structural[1]), str(rng.choice(structural[2]))
    if layer in {"two_step_repair", "deceptive_hard_negative"} and normalized != "zip":
        fallback_name = "structural_directory" if layer == "two_step_repair" else "hard_negative"
        fallback = next(item for item in PROFILE_LAYERS if item[0] == fallback_name)
        compatible_fallback = _profiles_for_format(fallback[0], fallback[2], normalized)
        return fallback[0], float(fallback[1]), str(rng.choice(compatible_fallback or fallback[2]))
    compatible = _profiles_for_format(layer, profiles, normalized)
    return layer, weight, str(rng.choice(compatible or profiles))


def _damage_layer_plan(rng: random.Random, fmt: str, per_sample: int) -> list[tuple[str, str, float, str, str]]:
    if per_sample <= 0:
        return []
    requested_layers: list[str] = []
    for layer, count in _layer_budget_for_format(fmt):
        requested_layers.extend([layer] * int(count))
    while len(requested_layers) < per_sample:
        requested_layers.append(_choose_damage_profile(rng, fmt)[0])
    rng.shuffle(requested_layers)
    requested_layers = requested_layers[:per_sample]
    output: list[tuple[str, str, float, str, str]] = []
    for requested_layer in requested_layers:
        layer_item = next((item for item in PROFILE_LAYERS if item[0] == requested_layer), PROFILE_LAYERS[0])
        layer, weight, profiles = layer_item
        actual_layer = layer
        skip_reason = ""
        if layer == "partial_recoverable" and not _supports_entry_partial(fmt):
            actual_layer = "structural_directory"
            skip_reason = "entry_partial_unavailable_for_format"
            layer_item = next(item for item in PROFILE_LAYERS if item[0] == actual_layer)
            _, weight, profiles = layer_item
        if layer in {"two_step_repair", "deceptive_hard_negative"} and _normalized_material_format(fmt) != "zip":
            actual_layer = "structural_directory" if layer == "two_step_repair" else "hard_negative"
            skip_reason = f"{layer}_zip_only"
            layer_item = next(item for item in PROFILE_LAYERS if item[0] == actual_layer)
            _, weight, profiles = layer_item
        compatible = _profiles_for_format(actual_layer, profiles, fmt)
        choices = compatible or profiles
        profile = str(rng.choice(choices))
        output.append((requested_layer, actual_layer, float(weight), profile, skip_reason))
    return output


def _layer_budget_for_format(fmt: str) -> tuple[tuple[str, int], ...]:
    if _normalized_material_format(fmt) == "zip":
        return ZIP_LAYER_BUDGET
    return DEFAULT_LAYER_BUDGET


def _normalized_material_format(fmt: str) -> str:
    return str(fmt or "").strip().lower().replace("_", ".")


def _supports_entry_partial(fmt: str) -> bool:
    normalized = _normalized_material_format(fmt)
    return normalized in {"zip", "tar"}


def _profiles_for_format(layer: str, profiles: tuple[str, ...], fmt: str) -> tuple[str, ...]:
    normalized = _normalized_material_format(fmt)
    if normalized == "zip":
        zip_profiles = tuple(item for item in profiles if item.startswith("zip_"))
        return zip_profiles or profiles
    if layer != "partial_recoverable":
        return tuple(item for item in profiles if not item.startswith("zip_")) or profiles
    if normalized == "tar":
        return tuple(item for item in profiles if item.startswith("tar_"))
    if normalized == "7z":
        return tuple(item for item in profiles if item.startswith("seven_zip_"))
    if normalized == "rar":
        return tuple(item for item in profiles if item.startswith("rar_"))
    return ()


def _source_archive_id(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    stem = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in path.stem)[:48]
    return f"{stem}_{digest}"


def _load_source_derivation(path: Path) -> dict[str, Any]:
    sidecar = Path(str(path) + ".derived.json")
    if not sidecar.is_file():
        return {}
    try:
        loaded = json.loads(sidecar.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(loaded, dict):
        return {}
    return {
        key: loaded.get(key)
        for key in (
            "sample_id",
            "source_material_dir",
            "material_format",
            "format",
            "method",
            "level",
            "solid",
            "tool",
            "tool_path",
            "output_name",
            "sha256",
            "size",
            "command",
            "zip_variant",
            "zip_container_tags",
            "zip_tool",
            "zip_method",
            "zip_level",
            "zip_structure_features",
            "zip_split",
            "zip_password",
        )
        if key in loaded
    }


def _skipped_record(
    source: Path,
    fmt: str,
    source_archive_id: str,
    variant_index: int,
    profile: str,
    exc: Exception,
    material_format: str = "",
    material_sample_id: str = "",
    *,
    damage_layer: str = "",
    damage_layer_weight: float = 0.0,
    requested_damage_layer: str = "",
    actual_damage_layer: str = "",
    skip_reason: str = "",
) -> dict[str, Any]:
    record = {
        "schema_version": 1,
        "status": "skipped",
        "source_archive_id": source_archive_id,
        "source_path": str(source),
        "source_archive_name": source.name,
        "material_format": material_format,
        "material_sample_id": material_sample_id,
        "format": fmt,
        "variant_index": variant_index,
        "damage_profile": profile,
        "damage_layer": damage_layer,
        "requested_damage_layer": requested_damage_layer or damage_layer,
        "actual_damage_layer": actual_damage_layer or damage_layer,
        "damage_layer_weight": damage_layer_weight,
        "skip_reason": skip_reason,
        "error": str(exc),
    }
    source_derivation = _load_source_derivation(source)
    if source_derivation:
        record["source_derivation"] = source_derivation
        _copy_zip_derivation_fields(record, source_derivation)
    return record


def _pretty_path(path: Path) -> Path:
    suffix = "".join(path.suffixes)
    if suffix:
        return path.with_name(path.name.removesuffix(suffix) + ".pretty.json")
    return path.with_name(path.name + ".pretty.json")


if __name__ == "__main__":
    raise SystemExit(main())