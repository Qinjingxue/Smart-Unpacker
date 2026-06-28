from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import random
import shutil
import struct
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MATERIAL_ROOT = Path("repair_training") / "material" / "seven_zip"
DEFAULT_DISTRIBUTION = Path("repair_training") / "formats" / "seven_zip" / "distributions" / "damage_distribution_seven_zip_root_transition_v2.json"
SEVEN_Z_MAGIC = b"7z\xbc\xaf\x27\x1c"
PASSWORD = "secret"


@dataclass(frozen=True)
class Mutation:
    name: str
    op: str
    offset: int
    size: int
    zone: str
    expected_effect: str
    logical_offset: int | None = None
    part_path: str | None = None
    part_offset: int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "operation": self.op,
            "offset": self.offset,
            "size": self.size,
            "zone": self.zone,
            "expected_effect": self.expected_effect,
        }
        if self.logical_offset is not None:
            payload["logical_offset"] = self.logical_offset
        if self.part_path:
            payload["part_path"] = self.part_path
        if self.part_offset is not None:
            payload["part_offset"] = self.part_offset
        return payload


@dataclass(frozen=True)
class SourceVariant:
    name: str
    path: Path
    expected_files: dict[str, bytes]
    tags: list[str]
    compression_method: str = "LZMA2"
    compression_level: int = 5
    solid: bool = False
    encoded_header: bool = False
    encrypted: bool = False
    sfx: bool = False
    split: bool = False
    parts: list[Path] | None = None
    source_id: str = ""
    source_files: list[str] | None = None
    sfx_generation_mode: str = ""
    password: str | None = None

    def to_manifest_row(self) -> dict[str, Any]:
        return {
            "variant_id": self.name,
            "source_id": self.source_id or self.name,
            "archive_path": str(self.path.resolve()),
            "parts": [
                {"path": str(path.resolve()), "role": "volume" if index else "main", "volume_number": index + 1}
                for index, path in enumerate(self.parts or [self.path])
            ],
            "expected_files": _expected_files_manifest(self.expected_files),
            "container_tags": list(self.tags),
            "compression_method": self.compression_method,
            "compression_level": self.compression_level,
            "solid": self.solid,
            "encoded_header": self.encoded_header,
            "encrypted": self.encrypted,
            "password_present": bool(self.password),
            "sfx": self.sfx,
            "split": self.split,
            "source_files": list(self.source_files or []),
            "sfx_generation_mode": self.sfx_generation_mode,
        }

    @classmethod
    def from_manifest_row(cls, row: dict[str, Any]) -> "SourceVariant":
        expected_files = {
            str(name): b""
            for name in (row.get("expected_files") or {})
        }
        for name, meta in (row.get("expected_files") or {}).items():
            if isinstance(meta, dict) and meta.get("bytes_b64"):
                import base64

                expected_files[str(name)] = base64.b64decode(str(meta.get("bytes_b64") or ""))
        parts = [
            Path(str(item.get("path") or ""))
            for item in row.get("parts") or []
            if isinstance(item, dict) and item.get("path")
        ]
        return cls(
            name=str(row.get("variant_id") or Path(str(row.get("archive_path") or "")).stem),
            path=Path(str(row.get("archive_path") or "")),
            expected_files=expected_files,
            tags=[str(item) for item in row.get("container_tags") or [] if str(item)],
            compression_method=str(row.get("compression_method") or "LZMA2"),
            compression_level=_int_default(row.get("compression_level"), 5),
            solid=bool(row.get("solid")),
            encoded_header=bool(row.get("encoded_header")),
            encrypted=bool(row.get("encrypted")),
            sfx=bool(row.get("sfx")),
            split=bool(row.get("split")),
            parts=parts or None,
            source_id=str(row.get("source_id") or ""),
            source_files=[str(item) for item in row.get("source_files") or [] if str(item)],
            sfx_generation_mode=str(row.get("sfx_generation_mode") or ""),
            password=PASSWORD if row.get("password_present") else None,
        )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    seed = _resolve_seed(args.seed)
    rng = random.Random(seed)
    material_root = Path(args.material_root).resolve()
    if args.clean:
        _fast_rmtree(material_root)
    material_root.mkdir(parents=True, exist_ok=True)
    tool = _find_7z()
    distribution_path = Path(args.profile_distribution)
    if not distribution_path.is_absolute():
        distribution_path = REPO_ROOT / distribution_path
    profile_counts, profile_meta = _load_distribution(distribution_path)
    profiles = _expanded_profiles(profile_counts, rng, limit=int(args.limit or 0))
    source_root = material_root / "sources"
    variants = _ensure_source_variants(source_root, tool, args, rng)
    _validate_clean_variant_matrix(variants, strict=_strict_v2_distribution(distribution_path) and not args.clean_variant_limit)
    if args.clean_only:
        report = _distribution_report([], distribution_path, seed, variants)
        report_path = Path(args.distribution_report or material_root / _default_report_name(distribution_path))
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
        print(json.dumps({
            "format": "seven_zip",
            "records": 0,
            "clean_variants": len(variants),
            "clean_manifest": str((source_root / "clean_archive_manifest.jsonl").resolve()),
            "distribution_report": str(report_path.resolve()),
            "material_root": str(material_root.resolve()),
            "seed": seed,
        }, ensure_ascii=False, sort_keys=True))
        return 0
    damaged_root = material_root / "damaged"
    damaged_root.mkdir(parents=True, exist_ok=True)
    manifest_path = Path(args.manifest or material_root / "damage_manifest.jsonl")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    variant_usage: Counter[str] = Counter()
    profile_variant_usage: dict[str, Counter[str]] = defaultdict(Counter)
    for index, profile in enumerate(profiles):
        meta = dict(profile_meta.get(profile) or {})
        variant = _choose_variant(
            profile,
            variants,
            rng,
            meta=meta,
            variant_usage=variant_usage,
            profile_variant_usage=profile_variant_usage,
        )
        variant_usage[variant.name] += 1
        profile_variant_usage[profile][variant.name] += 1
        case_seed = rng.randrange(1, 2**31 - 1)
        record = _build_record(
            material_root=material_root,
            damaged_root=damaged_root,
            source=variant,
            profile=profile,
            meta=meta,
            index=index,
            seed=case_seed,
            rng=random.Random(case_seed),
        )
        records.append(record)
    with manifest_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
    _validate_profile_variant_coverage(profile_counts, variants)
    report = _distribution_report(records, distribution_path, seed, variants)
    report_path = Path(args.distribution_report or material_root / _default_report_name(distribution_path))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
    summary = {
        "format": "seven_zip",
        "records": len(records),
        "manifest": str(manifest_path.resolve()),
        "distribution_report": str(report_path.resolve()),
        "material_root": str(material_root.resolve()),
        "seed": seed,
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build 7z root-transition damaged material.")
    parser.add_argument("--material-root", default=str(DEFAULT_MATERIAL_ROOT))
    parser.add_argument("--profile-distribution", default=str(DEFAULT_DISTRIBUTION))
    parser.add_argument("--manifest", default="")
    parser.add_argument("--distribution-report", default="")
    parser.add_argument("--seed", default="20260513")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--clean", action="store_true", help="Delete existing seven_zip material before generation.")
    parser.add_argument("--source-material-root", default=str(Path("repair_training") / "source_material"))
    parser.add_argument("--clean-variant-limit", type=int, default=0)
    parser.add_argument("--archive-variant-config", default="")
    parser.add_argument("--skip-clean-build", action="store_true")
    parser.add_argument("--clean-only", action="store_true")
    return parser


def _resolve_seed(value: str) -> int:
    text = str(value or "").strip()
    if text.lower() == "random":
        return random.SystemRandom().randrange(1, 2**31 - 1)
    try:
        return int(text)
    except ValueError:
        return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)


def _load_distribution(path: Path) -> tuple[dict[str, int], dict[str, dict[str, Any]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    counts: dict[str, int] = {}
    meta: dict[str, dict[str, Any]] = {}
    for layer_name, default_layer in (("profiles", "basic"), ("compound_profiles", "compound"), ("physical_profiles", "physical")):
        raw = payload.get(layer_name) or {}
        for profile, value in raw.items():
            if isinstance(value, dict):
                count = int(value.get("count", 0))
                item_meta = {str(k): v for k, v in value.items() if k != "count"}
            else:
                count = int(value)
                item_meta = {}
            if count:
                counts[str(profile)] = counts.get(str(profile), 0) + count
                merged = dict(meta.get(str(profile)) or {})
                merged.update(item_meta)
                merged.setdefault("layer", default_layer)
                if default_layer != "basic":
                    merged.setdefault("compound_profile", default_layer == "compound")
                meta[str(profile)] = merged
    total = int(payload.get("total") or 0)
    if total and sum(counts.values()) != total:
        raise SystemExit(f"7z distribution count mismatch: expected {total}, got {sum(counts.values())}")
    return counts, meta


def _expanded_profiles(counts: dict[str, int], rng: random.Random, *, limit: int = 0) -> list[str]:
    profiles = [profile for profile, count in counts.items() for _ in range(count)]
    rng.shuffle(profiles)
    return profiles[:limit] if limit else profiles


def _find_7z() -> Path:
    candidates = [
        REPO_ROOT / "tools" / "7z.exe",
        REPO_ROOT / "dist" / "sunpack" / "tools" / "7z.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    found = shutil.which("7z.exe")
    if found:
        return Path(found)
    raise SystemExit("7z material generation requires tools/7z.exe or 7z.exe on PATH")


def _ensure_source_variants(root: Path, tool: Path, args: argparse.Namespace, rng: random.Random) -> dict[str, SourceVariant]:
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "clean_archive_manifest.jsonl"
    if args.skip_clean_build and manifest_path.is_file():
        return _load_clean_variants(manifest_path)
    if manifest_path.is_file() and not args.clean:
        loaded = _load_clean_variants(manifest_path)
        if loaded:
            return loaded
    matrix = _variant_matrix(Path(args.archive_variant_config) if args.archive_variant_config else None)
    if args.clean_variant_limit:
        matrix = matrix[: max(1, int(args.clean_variant_limit))]
    bundles = _source_bundles(Path(args.source_material_root), root / "inputs", max(1, min(12, len(matrix))), rng)
    variants: dict[str, SourceVariant] = {}
    for index, spec in enumerate(matrix):
        bundle = bundles[index % len(bundles)]
        variant = _create_source_variant(root, tool, spec, bundle)
        variants[variant.name] = variant
    _write_clean_manifest(manifest_path, variants)
    return variants


def _load_clean_variants(path: Path) -> dict[str, SourceVariant]:
    variants: dict[str, SourceVariant] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        variant = SourceVariant.from_manifest_row(row)
        if variant.path.is_file():
            variants[variant.name] = variant
    return variants


def _write_clean_manifest(path: Path, variants: dict[str, SourceVariant]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for variant in variants.values():
            handle.write(json.dumps(variant.to_manifest_row(), ensure_ascii=False, sort_keys=True, default=str) + "\n")


def _variant_matrix(config_path: Path | None = None) -> list[dict[str, Any]]:
    if config_path is not None and str(config_path) and config_path.is_file():
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        variants = payload.get("variants") if isinstance(payload, dict) else payload
        if isinstance(variants, list) and variants:
            return [dict(item) for item in variants if isinstance(item, dict)]
    variants: list[dict[str, Any]] = []
    methods = ["LZMA2", "LZMA", "PPMd", "BZip2", "Copy"]
    levels = [0, 1, 5, 9]
    skipped_normal = {("LZMA2", 5), ("LZMA", 0), ("PPMd", 5), ("Copy", 9)}
    for index, method in enumerate(methods):
        for level in levels:
            if (method, level) in skipped_normal:
                continue
            variants.append({
                "name": f"normal_{method.lower()}_mx{level}_{'solid' if (index + level) % 2 == 0 else 'nonsolid'}",
                "method": method,
                "level": level,
                "solid": (index + level) % 2 == 0,
            })
    variants.extend([
        {"name": "split_lzma2_mx5", "method": "LZMA2", "level": 5, "solid": False, "split": True, "volume_size": "1k"},
        {"name": "split_lzma2_mx9_encrypted_encoded", "method": "LZMA2", "level": 9, "solid": False, "split": True, "encrypted": True, "encoded": True, "volume_size": "1k"},
        {"name": "split_lzma_mx1", "method": "LZMA", "level": 1, "solid": False, "split": True, "volume_size": "1k"},
        {"name": "split_ppmd_mx5_encrypted", "method": "PPMd", "level": 5, "solid": False, "split": True, "encrypted": True, "volume_size": "1k"},
        {"name": "split_bzip2_mx9_solid", "method": "BZip2", "level": 9, "solid": True, "split": True, "volume_size": "1k"},
        {"name": "split_copy_mx0", "method": "Copy", "level": 0, "solid": False, "split": True, "volume_size": "1k"},
        {"name": "split_sfx_lzma2_mx1_encrypted_encoded", "method": "LZMA2", "level": 1, "solid": False, "split": True, "sfx": True, "encrypted": True, "encoded": True, "volume_size": "1k"},
        {"name": "split_sfx_lzma2_mx5", "method": "LZMA2", "level": 5, "solid": False, "split": True, "sfx": True, "volume_size": "1k"},
        {"name": "split_sfx_lzma_mx1_encrypted", "method": "LZMA", "level": 1, "solid": False, "split": True, "sfx": True, "encrypted": True, "volume_size": "1k"},
        {"name": "split_sfx_ppmd_mx5_encrypted", "method": "PPMd", "level": 5, "solid": False, "split": True, "sfx": True, "encrypted": True, "volume_size": "1k"},
        {"name": "split_sfx_bzip2_mx9_encrypted", "method": "BZip2", "level": 9, "solid": False, "split": True, "sfx": True, "encrypted": True, "volume_size": "1k"},
        {"name": "sfx_lzma2_mx5", "method": "LZMA2", "level": 5, "solid": False, "sfx": True},
        {"name": "sfx_lzma2_mx9_encoded", "method": "LZMA2", "level": 9, "solid": False, "sfx": True, "encoded": True},
        {"name": "sfx_lzma_mx1_solid", "method": "LZMA", "level": 1, "solid": True, "sfx": True},
        {"name": "sfx_ppmd_mx5", "method": "PPMd", "level": 5, "solid": False, "sfx": True},
        {"name": "sfx_bzip2_mx1_solid", "method": "BZip2", "level": 1, "solid": True, "sfx": True},
        {"name": "sfx_copy_mx0", "method": "Copy", "level": 0, "solid": False, "sfx": True},
        {"name": "sfx_lzma2_mx5_encrypted", "method": "LZMA2", "level": 5, "solid": False, "sfx": True, "encrypted": True},
        {"name": "sfx_lzma2_mx9_encrypted_encoded", "method": "LZMA2", "level": 9, "solid": False, "sfx": True, "encrypted": True, "encoded": True},
        {"name": "sfx_ppmd_mx5_encrypted_encoded", "method": "PPMd", "level": 5, "solid": False, "sfx": True, "encrypted": True, "encoded": True},
        {"name": "encrypted_lzma2_mx5", "method": "LZMA2", "level": 5, "solid": False, "encrypted": True},
        {"name": "encrypted_lzma2_mx9_encoded", "method": "LZMA2", "level": 9, "solid": False, "encrypted": True, "encoded": True},
        {"name": "encrypted_lzma_mx1_solid", "method": "LZMA", "level": 1, "solid": True, "encrypted": True},
        {"name": "encrypted_ppmd_mx5", "method": "PPMd", "level": 5, "solid": False, "encrypted": True},
        {"name": "encrypted_bzip2_mx1_solid", "method": "BZip2", "level": 1, "solid": True, "encrypted": True},
        {"name": "encrypted_copy_mx0", "method": "Copy", "level": 0, "solid": False, "encrypted": True},
        {"name": "encrypted_split_lzma2_mx5", "method": "LZMA2", "level": 5, "solid": False, "encrypted": True, "split": True, "volume_size": "1k"},
        {"name": "encrypted_sfx_lzma2_mx9_encoded", "method": "LZMA2", "level": 9, "solid": False, "encrypted": True, "sfx": True, "encoded": True},
        {"name": "encoded_lzma2_mx5", "method": "LZMA2", "level": 5, "solid": False, "encoded": True},
        {"name": "encoded_lzma2_mx9_solid", "method": "LZMA2", "level": 9, "solid": True, "encoded": True},
        {"name": "encoded_ppmd_mx1", "method": "PPMd", "level": 1, "solid": False, "encoded": True},
        {"name": "encoded_bzip2_mx5_solid", "method": "BZip2", "level": 5, "solid": True, "encoded": True},
    ])
    return variants


def _source_bundles(source_root: Path, work_root: Path, count: int, rng: random.Random) -> list[tuple[str, Path, dict[str, bytes], list[str]]]:
    files = [
        path for path in source_root.rglob("*")
        if path.is_file() and path.name not in {"derived_manifest.jsonl", "derived_manifest.pretty.json"} and path.stat().st_size <= 512 * 1024
    ]
    rng.shuffle(files)
    if not files:
        files = []
    bundles = []
    for index in range(count):
        bundle_root = work_root / f"source_bundle_{index:02d}"
        if bundle_root.exists():
            _fast_rmtree(bundle_root)
        bundle_root.mkdir(parents=True, exist_ok=True)
        expected: dict[str, bytes] = {}
        source_files: list[str] = []
        selected = files[index * 3:(index * 3) + 3] or files[:3]
        for file_index, source in enumerate(selected):
            data = source.read_bytes()
            rel = Path(f"src_{file_index}_{_safe_name(source.name)}")
            target = bundle_root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            expected[str(rel).replace("\\", "/")] = data
            source_files.append(str(source.resolve()))
        generated = {
            "alpha.txt": b"alpha payload\n" * 8,
            "nested/gamma.txt": b"gamma payload\n" * 5,
            "unicodé/数据.txt": "payload unicode\n".encode("utf-8") * 4,
            "empty.dat": b"",
        }
        for name, data in generated.items():
            target = bundle_root / Path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            expected[name] = data
        bundles.append((f"source_bundle_{index:02d}", bundle_root, expected, source_files))
    return bundles


def _create_source_variant(root: Path, tool: Path, spec: dict[str, Any], bundle: tuple[str, Path, dict[str, bytes], list[str]]) -> SourceVariant:
    source_id, input_dir, expected, source_files = bundle
    name = str(spec.get("name") or f"variant_{source_id}")
    method = str(spec.get("method") or "LZMA2")
    level = _int_default(spec.get("level"), 5)
    solid = bool(spec.get("solid"))
    encoded = bool(spec.get("encoded"))
    encrypted = bool(spec.get("encrypted"))
    sfx = bool(spec.get("sfx"))
    split = bool(spec.get("split"))
    volume_size = str(spec.get("volume_size") or "1k")
    archive_dir = root / "archives"
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive = archive_dir / (f"{name}.exe" if sfx else f"{name}.7z")
    for old in archive_dir.glob(f"{name}.7z*"):
        old.unlink()
    if archive.is_file():
        archive.unlink()
    base_archive = archive_dir / f"{name}.7z"
    cmd = [
        str(tool),
        "a",
        "-t7z",
        str(base_archive),
        ".",
        "-y",
        f"-mx={level}",
        f"-ms={'on' if solid else 'off'}",
        f"-m0={method}",
    ]
    if encoded:
        cmd.append("-mhc=on")
    if encrypted:
        cmd.extend([f"-p{PASSWORD}", "-mhe=on"])
    if split:
        cmd.append(f"-v{volume_size}")
    completed = subprocess.run(cmd, cwd=str(input_dir), capture_output=True, text=True)
    parts = sorted(archive_dir.glob(f"{base_archive.name}.*")) if split else [base_archive]
    if completed.returncode != 0 or not parts or not parts[0].is_file():
        raise SystemExit(f"7z source variant failed ({name}): {completed.stderr or completed.stdout}")
    sfx_mode = ""
    path = parts[0]
    if sfx:
        path, parts, sfx_mode = _make_sfx_variant(tool, base_archive, archive, parts)
    tags = ["solid_archive" if solid else "non_solid_archive", "utf16_names", "empty_streams"]
    if encoded:
        tags.append("encoded_header")
    if encrypted:
        tags.extend(["encrypted_header", "password_present"])
    if sfx:
        tags.extend(["sfx", "carrier_prefix", "carrier_archive", "embedded_archive"])
    if split:
        tags.extend(["split_archive", "split_sidecars_available"])
    return SourceVariant(
        name=name,
        path=path.resolve(),
        expected_files=expected,
        tags=_dedupe(tags),
        compression_method=method,
        compression_level=level,
        solid=solid,
        encoded_header=encoded,
        encrypted=encrypted,
        sfx=sfx,
        split=split,
        parts=[part.resolve() for part in parts],
        source_id=source_id,
        source_files=source_files,
        sfx_generation_mode=sfx_mode,
        password=PASSWORD if encrypted else None,
    )


def _make_sfx_variant(tool: Path, base_archive: Path, output: Path, parts: list[Path]) -> tuple[Path, list[Path], str]:
    sfx_module = tool.with_name("7z.sfx")
    if sfx_module.is_file() and parts:
        output.write_bytes(sfx_module.read_bytes() + parts[0].read_bytes())
        return output, [output, *parts[1:]], "real_sfx_module_split_prefix"
    if sfx_module.is_file() and base_archive.is_file():
        output.write_bytes(sfx_module.read_bytes() + base_archive.read_bytes())
        return output, [output], "real_sfx_module_concat"
    output.write_bytes(b"MZ-SUNPACK-TRAINING-SFX\r\n" + parts[0].read_bytes())
    return output, [output, *parts[1:]], "synthetic_prefix"


def _safe_name(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in name)[:80] or "file"


def _choose_variant(
    profile: str,
    variants: dict[str, SourceVariant],
    rng: random.Random,
    *,
    meta: dict[str, Any] | None = None,
    variant_usage: Counter[str] | None = None,
    profile_variant_usage: dict[str, Counter[str]] | None = None,
) -> SourceVariant:
    candidates = list(variants.values())
    requirements = _variant_requirements(profile, meta or {})
    for requirement in requirements:
        candidates = [variant for variant in candidates if _variant_matches_requirement(variant, requirement)]
    if not candidates:
        raise SystemExit(f"no 7z clean variant satisfies profile={profile!r} requirements={sorted(requirements)!r}")
    profile_usage = (profile_variant_usage or {}).get(profile, Counter())
    global_usage = variant_usage or Counter()
    jitter: dict[str, float] = {variant.name: rng.random() for variant in candidates}
    return min(candidates, key=lambda variant: (profile_usage[variant.name], global_usage[variant.name], jitter[variant.name], variant.name))


def _variant_requirements(profile: str, meta: dict[str, Any]) -> set[str]:
    profile_l = profile.lower()
    requirements = {str(item).lower() for item in meta.get("variant_requirements") or [] if str(item)}
    components = [str(item).lower() for item in meta.get("compound_components") or [] if str(item)]
    haystack = " ".join([profile_l, *components])
    if "split" in haystack:
        requirements.add("split")
    if "sfx" in haystack or "carrier" in haystack:
        requirements.add("sfx")
    if "encrypted" in haystack:
        requirements.add("encrypted")
    if "encoded" in haystack:
        requirements.add("encoded")
    if "non_solid" in haystack:
        requirements.add("non_solid")
    elif "solid" in haystack:
        requirements.add("solid")
    if "names" in haystack or "utf16" in haystack:
        requirements.add("utf16_names")
    if "empty" in haystack or "file_count" in haystack:
        requirements.add("empty_streams")
    return requirements


def _variant_matches_requirement(variant: SourceVariant, requirement: str) -> bool:
    if requirement == "split":
        return bool(variant.split)
    if requirement == "sfx":
        return bool(variant.sfx)
    if requirement == "encrypted":
        return bool(variant.encrypted)
    if requirement == "encoded":
        return bool(variant.encoded_header)
    if requirement == "solid":
        return bool(variant.solid)
    if requirement == "non_solid":
        return not bool(variant.solid)
    if requirement == "utf16_names":
        return any("utf16" in tag or "names" in tag for tag in variant.tags)
    if requirement == "empty_streams":
        return any("empty" in tag for tag in variant.tags)
    return requirement in variant.tags


def _build_record(
    *,
    material_root: Path,
    damaged_root: Path,
    source: SourceVariant,
    profile: str,
    meta: dict[str, Any],
    index: int,
    seed: int,
    rng: random.Random,
) -> dict[str, Any]:
    clean = _source_logical_bytes(source)
    data = bytearray(clean)
    mutations: list[Mutation] = []
    route_flags = list(meta.get("expected_route_facts") or [])
    components = list(meta.get("compound_components") or _profile_components(profile))
    for component in components:
        _apply_component(data, component, rng, mutations, route_flags)
    if not mutations:
        _apply_component(data, profile, rng, mutations, route_flags)
    route_flags = _dedupe([*route_flags, *_default_route_flags(profile, source)])
    structure = _structure_from_flags(route_flags)
    structure["route_evidence_flags"] = route_flags
    structure["source_variant"] = source.name
    structure["compression_method"] = source.compression_method
    structure["compression_level"] = source.compression_level
    structure["solid_archive"] = bool(source.solid)
    structure["non_solid_archive"] = not bool(source.solid)
    structure["encoded_header_present"] = bool(source.encoded_header)
    structure["split_sidecars_available"] = bool(source.split)
    tags = _dedupe([*source.tags, *_container_tags(route_flags)])
    profile_dir = damaged_root / profile
    profile_dir.mkdir(parents=True, exist_ok=True)
    case_id = f"seven_zip_{profile}_{index:04d}"
    damaged_path = profile_dir / (f"{case_id}.exe" if source.sfx else f"{case_id}.7z")
    damaged_parts: list[dict[str, Any]] = []
    if source.split:
        damaged_parts = _write_split_parts_for_damage(source, damaged_path, bytes(data), mutations)
    else:
        damaged_path.write_bytes(bytes(data))
    expected_files = _expected_files_manifest(source.expected_files)
    physical_complete_expected = bool(meta.get("physical_complete_expected", not profile.startswith("partial_")))
    password = source.password
    if "wrong_or_missing_password" in profile:
        password = None
    damaged_input = {"kind": "file", "path": str(damaged_path.resolve()), "format_hint": "7z"}
    if password:
        damaged_input["password"] = password
    if source.split:
        damaged_input.update({
            "parts": damaged_parts,
            "use_parts_only": True,
        })
    record = {
        "schema_version": 1,
        "sample_id": case_id,
        "query_id": f"{case_id}:0",
        "source_archive_id": source.source_id or source.path.stem,
        "source_path": str(source.path),
        "source_archive_name": source.path.name,
        "damaged_path": str(damaged_path.resolve()),
        "damaged_file_name": damaged_path.name,
        "damage_json_path": str((profile_dir / f"{case_id}.damage.json").resolve()),
        "material_format": "seven_zip",
        "material_sample_id": "generated",
        "format": "seven_zip",
        "seed": seed,
        "variant_index": index,
        "damage_profile": profile,
        "profile_capability": "physical_partial" if not physical_complete_expected else "structural_repair",
        "difficulty_tags": [str(meta.get("layer") or "basic"), source.name],
        "oracle_strength": "payload_hash",
        "clean_sha256": hashlib.sha256(clean).hexdigest(),
        "corrupted_sha256": hashlib.sha256(bytes(data)).hexdigest(),
        "clean_input": {"kind": "file", "path": str(source.path), "format_hint": "7z", **({"password": source.password} if source.password else {})},
        "damaged_input": damaged_input,
        "corruption_plan": [mutation.to_dict() for mutation in mutations],
        "damage_flags": route_flags,
        "runtime_damage_flags": route_flags,
        "seven_zip_structure_features": structure,
        "seven_zip_container_tags": tags,
        "source_derivation": {
            "source_variant": source.name,
            "source_id": source.source_id,
            "source_files": list(source.source_files or []),
            "compression_method": source.compression_method,
            "compression_level": source.compression_level,
            "solid": source.solid,
            "encoded_header": source.encoded_header,
            "encrypted": source.encrypted,
            "sfx": source.sfx,
            "split": source.split,
            "sfx_generation_mode": source.sfx_generation_mode,
            "split_entry_path": str(damaged_parts[0].get("path") if damaged_parts else damaged_path.resolve()),
            "sfx_carrier_entry_path": str(damaged_path.resolve()) if source.sfx else "",
            "layer": str(meta.get("layer") or ("physical" if not physical_complete_expected else ("compound" if meta.get("compound_profile", profile.startswith("compound_")) else "basic"))),
            "variant_requirements": sorted(_variant_requirements(profile, meta)),
            "compound_profile": bool(meta.get("compound_profile", profile.startswith("compound_"))),
            "compound_components": components,
            "expected_min_steps": int(meta.get("expected_min_steps", 1)),
            "physical_complete_expected": physical_complete_expected,
        },
        "compound_profile": bool(meta.get("compound_profile", profile.startswith("compound_"))),
        "compound_components": components,
        "expected_min_steps": int(meta.get("expected_min_steps", 1)),
        "physical_complete_expected": physical_complete_expected,
        "oracle": {
            "expected_statuses": ["complete"] if physical_complete_expected else ["partial", "no_progress", "hard_negative"],
            "expected_module": "",
            "output_required": True,
            "expected_files": expected_files,
        },
    }
    if password:
        record["password"] = password
    (profile_dir / f"{case_id}.damage.json").write_text(json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return record


def _profile_components(profile: str) -> list[str]:
    profile_l = profile.lower()
    mapping = {
        "start_header_crc": ["start_header_crc"],
        "next_header_crc": ["next_header_crc"],
        "signature_header_version": ["signature_header_version"],
        "trailing_junk": ["trailing_junk"],
        "sfx_prefix": ["sfx_prefix"],
        "next_header_offset": ["next_header_offset"],
        "next_header_size": ["next_header_size"],
        "pack_stream_offset": ["pack_stream_offset"],
        "pack_stream_size": ["pack_stream_size"],
        "encoded_header_stream_crc": ["encoded_header_stream_crc"],
        "stream_crc": ["stream_crc"],
        "empty_stream_flags": ["empty_stream_flags"],
        "file_count_metadata": ["file_count_metadata"],
        "names_utf16": ["names_utf16"],
    }
    for key, components in mapping.items():
        if key in profile_l:
            return components
    if "payload" in profile_l or "block" in profile_l:
        return ["payload_partial"]
    return [profile_l]


def _apply_component(data: bytearray, component: str, rng: random.Random, mutations: list[Mutation], route_flags: list[str]) -> None:
    component = component.lower()
    sig = _signature_offset(data)
    if component in {"sfx_prefix", "carrier_prefix"}:
        prefix = b"MZ-SUNPACK-7Z" + rng.randbytes(8)
        data[:0] = prefix
        mutations.append(Mutation("insert_7z_sfx_prefix", "insert", 0, len(prefix), "7z.sfx.prefix", "7z payload is embedded behind a carrier prefix"))
        route_flags.extend(["carrier_prefix", "carrier_archive", "sfx", "embedded_archive"])
        return
    sig = _signature_offset(data)
    if component == "trailing_junk":
        junk = b"7ZTAIL" + rng.randbytes(16)
        offset = len(data)
        data.extend(junk)
        mutations.append(Mutation("append_7z_trailing_junk", "append", offset, len(junk), "archive.tail", "extra bytes after the trusted 7z stream"))
        route_flags.extend(["trailing_junk", "boundary_unreliable"])
    elif component == "signature_header_version":
        _replace(data, sig + 6, b"\x01\xff", mutations, "corrupt_7z_signature_header_version", "7z.signature_header.version", "signature header version is invalid")
        route_flags.append("signature_header_version_bad")
    elif component == "start_header_crc":
        _replace(data, sig + 8, b"\0\0\0\0", mutations, "corrupt_7z_start_header_crc", "7z.start_header_crc", "start header CRC is invalid")
        route_flags.append("start_header_crc_bad")
    elif component == "next_header_crc":
        _replace(data, sig + 28, b"\0\0\0\0", mutations, "corrupt_7z_next_header_crc", "7z.next_header_crc", "next header CRC is invalid")
        route_flags.append("next_header_crc_bad")
    elif component == "next_header_offset":
        value = _u64_at(data, sig + 12)
        _replace(data, sig + 12, struct.pack("<Q", value + 5), mutations, "corrupt_7z_next_header_offset", "7z.next_header_offset", "next header offset points to the wrong byte")
        route_flags.append("next_header_offset_bad")
    elif component == "next_header_size":
        value = max(1, _u64_at(data, sig + 20))
        _replace(data, sig + 20, struct.pack("<Q", value + 7), mutations, "corrupt_7z_next_header_size", "7z.next_header_size", "next header size is wrong")
        route_flags.append("next_header_size_bad")
    elif component in {"pack_stream_offset", "pack_stream_size", "stream_crc", "encoded_header_stream_crc", "empty_stream_flags", "file_count_metadata", "names_utf16", "folder_graph", "bad_folder"}:
        start, end = _next_header_range(data, sig)
        offset = _bounded_offset(start, end, rng)
        data[offset] ^= 0x5A
        zone = f"7z.{component}"
        mutations.append(Mutation(f"corrupt_7z_{component}", "replace_byte", offset, 1, zone, f"{component} metadata is inconsistent"))
        route_flags.extend(_component_flags(component))
    elif component in {"payload_partial", "payload_damage", "middle_block_damage", "many_stream_payload_damage", "solid_prefix", "all_payload_blocks_bad"}:
        start, end = _payload_range(data, sig)
        offset = _bounded_offset(start, end, rng)
        data[offset] ^= 0x31
        mutations.append(Mutation("flip_7z_payload_byte", "replace_byte", offset, 1, "7z.payload", "packed stream payload bytes are physically damaged"))
        route_flags.extend(["packed_stream_bad", "payload_crc_bad", "crc_error", "partial_recovery_possible"])
    elif component in {"tail_truncated", "pack_stream_truncated"}:
        cut = max(sig + 40, len(data) - max(16, len(data) // 8))
        removed = max(0, len(data) - cut)
        del data[cut:]
        mutations.append(Mutation("truncate_7z_stream_tail", "truncate", cut, removed, "7z.stream_tail", "7z stream tail is physically truncated"))
        route_flags.extend(["packed_stream_bad", "payload_crc_bad", "partial_recovery_possible"])
    elif component in {"encoded_header_unreadable", "next_header_damage", "payload_overlap"}:
        start, end = _next_header_range(data, sig)
        offset = _bounded_offset(start, end, rng)
        data[offset] ^= 0xA5
        mutations.append(Mutation(f"corrupt_7z_{component}", "replace_byte", offset, 1, "7z.next_header", "next header is unreadable or overlaps payload"))
        route_flags.extend(["encoded_header_unreadable", "next_header_out_of_range"])
    elif component in {"encrypted_known_password", "encrypted_missing_or_wrong_password", "encrypted"}:
        route_flags.extend(["encrypted_header", "password_present" if component == "encrypted_known_password" else "password_required"])
    else:
        start, end = _payload_range(data, sig)
        offset = _bounded_offset(start, end, rng)
        data[offset] ^= 0x17
        mutations.append(Mutation("fallback_7z_payload_damage", "replace_byte", offset, 1, "7z.payload", "fallback payload mutation keeps sample non-trivial"))
        route_flags.extend(["damaged", "payload_crc_bad"])


def _component_flags(component: str) -> list[str]:
    return {
        "pack_stream_offset": ["pack_stream_offset_bad"],
        "pack_stream_size": ["pack_stream_size_bad"],
        "stream_crc": ["stream_crc_bad", "substream_crc_bad"],
        "encoded_header_stream_crc": ["encoded_header_stream_crc_bad", "encoded_header_decodable"],
        "empty_stream_flags": ["empty_stream_flags_bad", "empty_file_flags_bad", "anti_item_flags_bad"],
        "file_count_metadata": ["file_count_metadata_bad"],
        "names_utf16": ["file_names_utf16_bad", "names_utf16_bad", "file_name_metadata_bad"],
        "folder_graph": ["folder_bind_pairs_bad", "folder_stream_counts_bad"],
        "bad_folder": ["bad_folder_detected", "verified_folder_available"],
    }.get(component, ["damaged"])


def _replace(data: bytearray, offset: int, payload: bytes, mutations: list[Mutation], name: str, zone: str, effect: str) -> None:
    if offset < 0 or offset + len(payload) > len(data):
        return
    data[offset:offset + len(payload)] = payload
    mutations.append(Mutation(name, "replace_bytes", offset, len(payload), zone, effect))


def _signature_offset(data: bytearray | bytes) -> int:
    offset = bytes(data).find(SEVEN_Z_MAGIC)
    return max(0, offset)


def _u64_at(data: bytearray, offset: int) -> int:
    if offset + 8 > len(data):
        return 0
    return struct.unpack_from("<Q", data, offset)[0]


def _next_header_range(data: bytearray, sig: int) -> tuple[int, int]:
    if sig + 32 > len(data):
        return max(0, sig), len(data)
    offset = sig + 32 + min(_u64_at(data, sig + 12), max(0, len(data) - sig - 32))
    size = min(_u64_at(data, sig + 20), max(0, len(data) - offset))
    if size <= 0:
        return max(sig + 32, 0), len(data)
    return int(offset), int(offset + size)


def _payload_range(data: bytearray, sig: int) -> tuple[int, int]:
    header_start, _ = _next_header_range(data, sig)
    start = min(len(data), sig + 32)
    end = max(start + 1, min(len(data), header_start))
    return start, end


def _bounded_offset(start: int, end: int, rng: random.Random) -> int:
    if end <= start:
        return max(0, start)
    return rng.randrange(start, end)


def _structure_from_flags(flags: list[str]) -> dict[str, Any]:
    output = {flag: True for flag in flags if flag.endswith("_bad") or flag in {
        "trailing_junk",
        "carrier_prefix",
        "carrier_archive",
        "sfx",
        "encoded_header_unreadable",
        "encoded_header_decodable",
        "solid_archive",
        "non_solid_archive",
        "encrypted_header",
        "password_required",
        "password_present",
        "partial_recovery_possible",
    }}
    if "solid_archive" not in output and "non_solid_archive" not in output:
        output["non_solid_archive"] = True
    return output


def _default_route_flags(profile: str, source: SourceVariant) -> list[str]:
    flags = ["seven_zip_signature_found"]
    flags.extend(source.tags)
    if source.password:
        flags.append("password_present")
    if "solid_archive" not in flags and "non_solid_archive" not in flags:
        flags.append("non_solid_archive")
    if profile.startswith("partial_"):
        flags.append("partial_recovery_possible")
    return flags


def _container_tags(flags: list[str]) -> list[str]:
    tags = []
    for flag in flags:
        if flag in {"solid_archive", "non_solid_archive", "encrypted_header", "carrier_prefix", "sfx", "encoded_header_present", "split_archive", "split_sidecars_available"}:
            tags.append(flag)
    return _dedupe(tags)


def _source_logical_bytes(source: SourceVariant) -> bytes:
    parts = list(source.parts or [])
    if source.split and parts:
        return b"".join(part.read_bytes() for part in parts)
    return source.path.read_bytes()


def _write_split_parts_for_damage(
    source: SourceVariant,
    damaged_path: Path,
    data: bytes,
    mutations: list[Mutation],
) -> list[dict[str, Any]]:
    parts = list(source.parts or [source.path])
    lengths = [part.stat().st_size if part.is_file() else 0 for part in parts]
    targets: list[Path] = []
    offset = 0
    for index, part in enumerate(parts):
        if index == 0:
            target = damaged_path
        else:
            suffix = "".join(part.suffixes[-2:]) or f".{index + 1:03d}"
            target = damaged_path.with_name(f"{damaged_path.stem}{suffix}")
        length = lengths[index] if index < len(lengths) else 0
        if index == len(parts) - 1:
            chunk = data[offset:]
        else:
            chunk = data[offset:offset + length]
        target.write_bytes(chunk)
        targets.append(target)
        offset += length
    _annotate_mutation_part_locations(mutations, targets, lengths)
    output = []
    for index, target in enumerate(targets):
        output.append({
            "path": str(target.resolve()),
            "role": "carrier" if index == 0 and source.sfx else ("main" if index == 0 else "volume"),
            "volume_number": index + 1,
            "index": index,
            "start": 0,
            "end": None,
        })
    return output


def _annotate_mutation_part_locations(mutations: list[Mutation], parts: list[Path], lengths: list[int]) -> None:
    annotated: list[Mutation] = []
    for mutation in mutations:
        part_path, part_offset = _logical_offset_to_part(mutation.offset, parts, lengths)
        annotated.append(Mutation(
            mutation.name,
            mutation.op,
            mutation.offset,
            mutation.size,
            mutation.zone,
            mutation.expected_effect,
            logical_offset=mutation.offset,
            part_path=str(part_path.resolve()) if part_path is not None else None,
            part_offset=part_offset,
        ))
    mutations[:] = annotated


def _logical_offset_to_part(offset: int, parts: list[Path], lengths: list[int]) -> tuple[Path | None, int | None]:
    cursor = 0
    for index, part in enumerate(parts):
        length = lengths[index] if index < len(lengths) else 0
        if offset < cursor + length or index == len(parts) - 1:
            return part, max(0, offset - cursor)
        cursor += length
    return None, None


def _expected_files_manifest(files: dict[str, bytes]) -> dict[str, dict[str, Any]]:
    import base64

    return {
        name: {
            "name": name,
            "size": len(data),
            "crc32": f"{binascii.crc32(data) & 0xffffffff:08x}",
            "sha256": hashlib.sha256(data).hexdigest(),
            "has_crc": True,
            "bytes_b64": base64.b64encode(data).decode("ascii"),
        }
        for name, data in files.items()
    }


def _distribution_report(records: list[dict[str, Any]], distribution: Path, seed: int, variants: dict[str, SourceVariant] | None = None) -> dict[str, Any]:
    profile_counts = Counter(str(record.get("damage_profile") or "") for record in records)
    layer_counts = Counter(str((record.get("source_derivation") or {}).get("layer") or "unknown") for record in records)
    expected_steps = Counter(str(record.get("expected_min_steps") or 1) for record in records)
    physical = Counter(str(bool(record.get("physical_complete_expected", True))).lower() for record in records)
    tags = Counter(tag for record in records for tag in record.get("seven_zip_container_tags") or [])
    password_counts = Counter("present" if record.get("password") else "absent" for record in records)
    source_derivations = [dict(record.get("source_derivation") or {}) for record in records]
    profile_variant_counts: dict[str, dict[str, int]] = {}
    for record in records:
        profile = str(record.get("damage_profile") or "")
        variant = str((record.get("source_derivation") or {}).get("source_variant") or "")
        if profile and variant:
            profile_variant_counts.setdefault(profile, {})
            profile_variant_counts[profile][variant] = profile_variant_counts[profile].get(variant, 0) + 1
    profile_variant_warnings = {
        profile: {
            "used_clean_variants": len(counts),
            "minimum_expected": min(4, profile_counts.get(profile, 0)),
        }
        for profile, counts in sorted(profile_variant_counts.items())
        if len(counts) < min(4, profile_counts.get(profile, 0))
    }
    damaged_presence = {
        "split": sum(1 for item in source_derivations if item.get("split")),
        "encrypted": sum(1 for item in source_derivations if item.get("encrypted")),
        "sfx": sum(1 for item in source_derivations if item.get("sfx")),
        "encoded_header": sum(1 for item in source_derivations if item.get("encoded_header")),
        "solid": sum(1 for item in source_derivations if item.get("solid")),
        "non_solid": sum(1 for item in source_derivations if not item.get("solid")),
    }
    variant_values = list((variants or {}).values())
    clean_coverage = {
        "variant_count": len(variant_values),
        "source_ids": sorted({variant.source_id for variant in variant_values if variant.source_id}),
        "compression_methods": dict(sorted(Counter(variant.compression_method for variant in variant_values).items())),
        "compression_levels": dict(sorted(Counter(str(variant.compression_level) for variant in variant_values).items())),
        "solid_counts": dict(sorted(Counter(str(bool(variant.solid)).lower() for variant in variant_values).items())),
        "sfx_counts": dict(sorted(Counter(str(bool(variant.sfx)).lower() for variant in variant_values).items())),
        "split_counts": dict(sorted(Counter(str(bool(variant.split)).lower() for variant in variant_values).items())),
        "encrypted_counts": dict(sorted(Counter(str(bool(variant.encrypted)).lower() for variant in variant_values).items())),
        "encoded_header_counts": dict(sorted(Counter(str(bool(variant.encoded_header)).lower() for variant in variant_values).items())),
        "warnings": _clean_variant_matrix_warnings(variants or {}),
    }
    return {
        "format": "seven_zip",
        "seed": seed,
        "distribution": str(distribution),
        "records": len(records),
        "clean_variant_coverage": clean_coverage,
        "profile_counts": dict(sorted(profile_counts.items())),
        "compound_profile_counts": dict(sorted(layer_counts.items())),
        "expected_min_steps_counts": dict(sorted(expected_steps.items())),
        "physical_complete_expected_counts": dict(sorted(physical.items())),
        "container_tag_counts": dict(sorted(tags.items())),
        "damaged_container_presence_counts": damaged_presence,
        "damaged_variant_coverage": {
            "source_variant_counts": dict(sorted(Counter(str(item.get("source_variant") or "") for item in source_derivations).items())),
            "source_id_counts": dict(sorted(Counter(str(item.get("source_id") or "") for item in source_derivations).items())),
            "compression_methods": dict(sorted(Counter(str(item.get("compression_method") or "") for item in source_derivations).items())),
            "compression_levels": dict(sorted(Counter(str(item.get("compression_level") or "") for item in source_derivations).items())),
            "profile_variant_counts": {profile: dict(sorted(counts.items())) for profile, counts in sorted(profile_variant_counts.items())},
            "profile_variant_warnings": profile_variant_warnings,
        },
        "password_counts": dict(sorted(password_counts.items())),
    }


def _validate_profile_variant_coverage(profile_counts: dict[str, int], variants: dict[str, SourceVariant]) -> None:
    missing: dict[str, str] = {}
    for profile in profile_counts:
        requirements = _variant_requirements(profile, {})
        if any(not any(_variant_matches_requirement(variant, requirement) for variant in variants.values()) for requirement in requirements):
            missing[profile] = f"requires clean variant matching {sorted(requirements)}"
    if missing:
        raise SystemExit(f"7z clean variant coverage is incomplete: {missing}")


def _validate_clean_variant_matrix(variants: dict[str, SourceVariant], *, strict: bool) -> None:
    warnings = _clean_variant_matrix_warnings(variants)
    if strict and warnings:
        raise SystemExit(f"7z V2 clean variant matrix is incomplete: {warnings}")


def _clean_variant_matrix_warnings(variants: dict[str, SourceVariant]) -> dict[str, Any]:
    values = list(variants.values())
    warnings: dict[str, Any] = {}
    methods = {variant.compression_method for variant in values}
    levels = {int(variant.compression_level) for variant in values}
    thresholds = {
        "variant_count": (len(values), 48),
        "split": (sum(1 for variant in values if variant.split), 8),
        "encrypted": (sum(1 for variant in values if variant.encrypted), 8),
        "sfx": (sum(1 for variant in values if variant.sfx), 8),
        "encoded_header": (sum(1 for variant in values if variant.encoded_header), 10),
        "solid": (sum(1 for variant in values if variant.solid), 16),
        "non_solid": (sum(1 for variant in values if not variant.solid), 24),
    }
    for name, (actual, minimum) in thresholds.items():
        if actual < minimum:
            warnings[name] = {"actual": actual, "minimum": minimum}
    expected_methods = {"LZMA2", "LZMA", "PPMd", "BZip2", "Copy"}
    if missing_methods := sorted(expected_methods - methods):
        warnings["missing_methods"] = missing_methods
    expected_levels = {0, 1, 5, 9}
    if missing_levels := sorted(expected_levels - levels):
        warnings["missing_levels"] = missing_levels
    return warnings


def _strict_v2_distribution(path: Path) -> bool:
    return "root_transition_v2" in path.name


def _default_report_name(distribution: Path) -> str:
    return "material_distribution_report_seven_zip_v2.json" if _strict_v2_distribution(distribution) else "material_distribution_report_seven_zip_v1.json"


def _int_default(value: Any, default: int) -> int:
    if value is None or value == "":
        return default
    return int(value)


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        text = str(value)
        if text and text not in output:
            output.append(text)
    return output


def _fast_rmtree(path: Path) -> None:
    if not path.exists():
        return
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Remove-Item -LiteralPath $args[0] -Recurse -Force -ErrorAction Stop", str(path)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )
        return
    except Exception:
        pass
    shutil.rmtree(path, ignore_errors=True)
