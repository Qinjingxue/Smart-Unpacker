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
    ("structural_directory", 0.30, ("structural_directory", "structural_metadata", "structural_index")),
    ("partial_recoverable", 0.25, ("partial_truncate", "partial_missing_directory", "partial_missing_volume")),
    ("hard_negative", 0.15, ("hard_negative_payload", "hard_negative_block_tail", "hard_negative_multi")),
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
                for variant_index in range(max(0, int(args.per_sample))):
                    layer, layer_weight, profile = _choose_damage_profile(rng, fmt)
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
                        record["damage_layer"] = layer
                        record["damage_layer_weight"] = layer_weight
                        if source_derivation:
                            record["source_derivation"] = source_derivation
                        damage_json_path.parent.mkdir(parents=True, exist_ok=True)
                        damage_json_path.write_text(json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
                        records.append(record)
                        summary["generated"] += 1
                    except Exception as exc:
                        records.append(_skipped_record(source, fmt, source_archive_id, variant_index, profile, exc, format_dir.name, sample_dir.name, damage_layer=layer, damage_layer_weight=layer_weight))
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
        for variant_index in range(max(0, per_source)):
            layer, layer_weight, profile = _choose_damage_profile(rng, fmt)
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
                records.append(_skipped_record(source, fmt, source_archive_id, variant_index, profile, exc, damage_layer=layer, damage_layer_weight=layer_weight))
                continue
            record = case.corpus_manifest_record(source_archive_id=source_archive_id, source_path=str(source), damage_profile=profile, variant_index=variant_index)
            record["damage_layer"] = layer
            record["damage_layer_weight"] = layer_weight
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
    for layer, weight, profiles in PROFILE_LAYERS:
        cumulative += float(weight)
        if roll <= cumulative:
            return _compatible_damage_profile(rng, layer, float(weight), profiles, fmt)
    layer, weight, profiles = PROFILE_LAYERS[-1]
    return _compatible_damage_profile(rng, layer, float(weight), profiles, fmt)


def _compatible_damage_profile(rng: random.Random, layer: str, weight: float, profiles: tuple[str, ...], fmt: str) -> tuple[str, float, str]:
    normalized = str(fmt or "").lower()
    if layer == "partial_recoverable" and normalized in {"gzip", "bzip2", "xz", "zstd"}:
        structural = next(item for item in PROFILE_LAYERS if item[0] == "structural")
        return structural[0], float(structural[1]), str(rng.choice(structural[2]))
    return layer, weight, str(rng.choice(profiles))


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
        "damage_layer_weight": damage_layer_weight,
        "error": str(exc),
    }
    source_derivation = _load_source_derivation(source)
    if source_derivation:
        record["source_derivation"] = source_derivation
    return record


def _pretty_path(path: Path) -> Path:
    suffix = "".join(path.suffixes)
    if suffix:
        return path.with_name(path.name.removesuffix(suffix) + ".pretty.json")
    return path.with_name(path.name + ".pretty.json")


if __name__ == "__main__":
    raise SystemExit(main())
