from __future__ import annotations

from dataclasses import dataclass
import bz2
import gzip
import hashlib
import io
import lzma
from pathlib import Path
import random
import struct
import tarfile
from typing import Any, Callable
import zlib

from repair_training.formats.base import TrainingFeatureSpec, TrainingFormatPlugin, TrainingLabelSchema
from sunpack.repair.model.diagnosis.atomic_format_graph import DEFINITIONS


@dataclass(frozen=True)
class DamageProfile:
    name: str
    flag: str
    expected_module: str
    mutate: Callable[[bytes], bytes]


FORMAT_PROFILES: dict[str, tuple[DamageProfile, ...]] = {
    "rar": (
        DamageProfile("main_header_crc", "rar_main_header_crc_bad", "rar_main_header_crc_repair", lambda b: _flip(b, 8)),
        DamageProfile("file_header_crc", "rar_file_header_crc_bad", "rar_file_header_crc_repair", lambda b: _flip(b, _rar_block_offset(b, 2))),
        DamageProfile("service_header_crc", "rar_service_header_crc_bad", "rar_service_header_crc_repair", lambda b: _flip(b, _rar_block_offset(b, 3))),
        DamageProfile("end_header_crc", "rar_end_header_crc_bad", "rar_end_header_crc_repair", lambda b: _flip(b, _rar_block_offset(b, 5))),
        DamageProfile("missing_end", "missing_end_block", "rar_end_block_repair", lambda b: _rar_drop_end(b)),
        DamageProfile("trailing_junk", "trailing_junk", "rar_trailing_junk_trim", lambda b: b + b"SUNPACK-JUNK"),
        DamageProfile("carrier_prefix", "carrier_prefix", "archive_carrier_crop_deep_recovery", lambda b: b"MZ-SUNPACK-CARRIER" + b),
    ),
    "tar": (
        DamageProfile("header_checksum", "tar_checksum_bad", "tar_single_header_checksum_repair", lambda b: _replace(b, 148, b"000000\0 ")),
        DamageProfile("pax_header", "pax_header_bad", "tar_pax_header_quarantine", lambda b: _tar_corrupt_pax(b)),
        DamageProfile("gnu_longname", "gnu_longname_bad", "tar_gnu_longname_quarantine", lambda b: _tar_corrupt_longname(b)),
        DamageProfile("sparse_header", "sparse_header_bad", "tar_sparse_entry_quarantine", lambda b: _tar_corrupt_sparse(b)),
        DamageProfile("missing_end", "missing_end_block", "tar_trailing_zero_block_repair", lambda b: b.rstrip(b"\0")),
        DamageProfile("trailing_junk", "trailing_junk", "tar_trailing_junk_trim", lambda b: b + b"SUNPACK-JUNK"),
        DamageProfile("truncated", "probably_truncated", "tar_truncated_partial_recovery", lambda b: b[:-700]),
    ),
    "gzip": (
        DamageProfile("header_crc", "gzip_header_crc_bad", "gzip_header_crc_repair", lambda b: _flip(b, 10)),
        DamageProfile("reserved_flags", "gzip_reserved_flags_set", "gzip_reserved_flags_repair", lambda b: _replace(b, 3, bytes([b[3] | 0xE0]))),
        DamageProfile("footer_crc", "gzip_footer_bad", "gzip_footer_fix", lambda b: _flip(b, len(b) - 8)),
        DamageProfile("trailing_junk", "trailing_junk", "gzip_trailing_junk_trim", lambda b: b + b"SUNPACK-JUNK"),
        DamageProfile("truncated", "probably_truncated", "gzip_truncated_partial_recovery", lambda b: b[:-6]),
        DamageProfile("deflate_damage", "deflate_resync", "gzip_deflate_member_resync", lambda b: _flip(b, min(len(b) - 9, 18))),
    ),
    "bzip2": (
        DamageProfile("block_size_header", "bzip2_block_size_bad", "bzip2_block_size_header_repair", lambda b: _replace(b, 3, b"0")),
        DamageProfile("trailing_junk", "trailing_junk", "bzip2_trailing_junk_trim", lambda b: b + b"SUNPACK-JUNK"),
        DamageProfile("truncated", "probably_truncated", "bzip2_truncated_partial_recovery", lambda b: b[:-8]),
        DamageProfile("block_damage", "bzip2_block_bad", "bzip2_block_salvage", lambda b: _flip(b, max(10, len(b) // 2))),
    ),
    "xz": (
        DamageProfile("header_crc", "xz_header_crc_bad", "xz_stream_header_crc_repair", lambda b: _flip(b, 8)),
        DamageProfile("footer_crc", "xz_footer_crc_bad", "xz_stream_footer_crc_repair", lambda b: _flip(b, len(b) - 12)),
        DamageProfile("trailing_junk", "trailing_junk", "xz_trailing_junk_trim", lambda b: b + b"SUNPACK-JUNK"),
        DamageProfile("truncated", "probably_truncated", "xz_truncated_partial_recovery", lambda b: b[:-8]),
        DamageProfile("block_damage", "xz_block_bad", "xz_block_salvage", lambda b: _flip(b, max(16, len(b) // 2))),
    ),
    "zstd": (
        DamageProfile("frame_damage", "zstd_frame_bad", "zstd_frame_salvage", lambda b: _flip(b, max(8, len(b) // 3))),
        DamageProfile("multiframe_damage", "zstd_multiframe_damage", "zstd_frame_salvage", lambda b: _flip(b, max(8, len(b) // 4))),
        DamageProfile("trailing_junk", "trailing_junk", "zstd_trailing_junk_trim", lambda b: b + b"SUNPACK-JUNK"),
        DamageProfile("truncated", "probably_truncated", "zstd_truncated_partial_recovery", lambda b: b[:-5]),
    ),
}


def make_training_plugin(format_name: str) -> TrainingFormatPlugin:
    profiles = FORMAT_PROFILES[format_name]

    def labels() -> TrainingLabelSchema:
        flags = tuple(sorted(DEFINITIONS[format_name].flag_zones))
        zones = tuple(sorted(set(DEFINITIONS[format_name].flag_zones.values())))
        return TrainingLabelSchema(labels=tuple(f"route:{flag}" for flag in flags) + tuple(f"family:{zone}" for zone in zones),
                                   metadata={"taxonomy": format_name, "schema_version": 2})

    def context(record: dict[str, Any]) -> dict[str, Any]:
        flags = sorted({str(v) for v in [*(record.get("damage_flags") or []), *(record.get("runtime_damage_flags") or [])] if str(v)})
        profile = str(record.get("damage_profile") or "")
        return {"payloads": {
            "archive": {"format": format_name},
            f"format.{format_name}": {"profile": profile, "route_evidence_flags": flags, "damaged_size": _input_size(record)},
            "training": {"sample_id": str(record.get("sample_id") or ""), "damage_profile": profile},
        }, "flags": {f"format.{format_name}.route_evidence": flags, "repair.damage": flags}}

    def generate(material_root: str | Path, workspace: str | Path, seed: int, per_source: int, limit: int) -> list[dict[str, Any]]:
        return generate_collection_records(format_name, material_root, workspace, seed, per_source, limit)

    return TrainingFormatPlugin(
        format_name=format_name, default_run_name=f"{format_name}_policy_lab",
        default_collection_budget={"workers": 2, "max_rounds": 4, "max_states": 16, "branch_top_k": 5, "root_branch_top_k": 5, "materialize_top_k": 6},
        model_output_subdir=Path("models") / f"{format_name}_policy_lab",
        collection_record_context=context, damage_label_schema=labels,
        damage_feature_spec=lambda: TrainingFeatureSpec(
            include_prefixes=("format", "runtime_context.", "diagnosis.", "repair_history."),
            categorical_paths=("format", "runtime_context.extraction_summary.failure_kind", "runtime_context.verification_summary.decision_hint"),
            ignore_prefixes=("runtime_context.archive_state.state", "job.source_input.path"),
        ),
        diagnostic_feature_groups=lambda: {"format": [f"format.{format_name}."], "runtime": ["runtime_context."]},
        diagnostic_profile_pairs=lambda: [],
        diagnostic_focus_labels=lambda: [f"route:{profile.flag}" for profile in profiles],
        damage_eval_profile_plan=lambda seed, count: [profiles[(seed + index) % len(profiles)].name for index in range(count)],
        generate_collection_records=generate,
        damage_eval_metadata=lambda: {"format": format_name, "profiles": [profile.name for profile in profiles]},
    )


def generate_collection_records(format_name: str, material_root: str | Path, workspace: str | Path,
                                seed: int, per_source: int, limit: int) -> list[dict[str, Any]]:
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    profiles = list(FORMAT_PROFILES[format_name])
    rng.shuffle(profiles)
    count = limit if limit > 0 else max(len(profiles), len(profiles) * max(1, per_source))
    records: list[dict[str, Any]] = []
    for index in range(count):
        profile = profiles[index % len(profiles)]
        clean = build_clean_archive(format_name, profile.name, index)
        damaged = profile.mutate(clean)
        clean_path = workspace / f"{format_name}_{index:04d}_clean.{_extension(format_name)}"
        damaged_path = workspace / f"{format_name}_{index:04d}_{profile.name}.{_extension(format_name)}"
        clean_path.write_bytes(clean)
        damaged_path.write_bytes(damaged)
        records.append({
            "sample_id": f"{format_name}-{seed}-{index}", "query_id": f"{format_name}-{seed}-{index}",
            "format": format_name, "material_format": format_name, "damage_profile": profile.name,
            "damage_layer": DEFINITIONS[format_name].flag_zones.get(profile.flag, "archive"),
            "damage_flags": [profile.flag], "runtime_damage_flags": [profile.flag],
            "expected_route_facts": [profile.flag], "expected_module": profile.expected_module,
            "expected_min_steps": 1, "oracle_strength": "exact", "difficulty_tags": ["synthetic", "atomic"],
            "source_archive_id": hashlib.sha256(clean).hexdigest(), "source_path": str(clean_path),
            "clean_sha256": hashlib.sha256(clean).hexdigest(), "corrupted_sha256": hashlib.sha256(damaged).hexdigest(),
            "damaged_input": {"kind": "file", "path": str(damaged_path), "format_hint": format_name},
            "corruption_plan": [{"name": profile.name, "kind": profile.flag, "zone": profile.flag,
                                   "expected_effect": profile.expected_module}],
            f"{format_name}_structure_features": {"clean_size": len(clean), "damaged_size": len(damaged), "profile": profile.name},
        })
    return records


def build_clean_archive(format_name: str, profile: str, index: int = 0) -> bytes:
    payload = (f"sunpack-{format_name}-{profile}-{index}\n" * 64).encode()
    if format_name == "rar": return _rar5_archive()
    if format_name == "tar": return _tar_archive(payload, profile)
    if format_name == "gzip": return _gzip_with_fhcrc(payload)
    if format_name == "bzip2": return bz2.compress(payload, compresslevel=9)
    if format_name == "xz": return lzma.compress(payload, format=lzma.FORMAT_XZ)
    if format_name == "zstd":
        import zstandard

        compressor = zstandard.ZstdCompressor(level=3, write_checksum=True)
        return compressor.compress(payload) + (compressor.compress(payload[::-1]) if profile == "multiframe_damage" else b"")
    raise ValueError(format_name)


def _rar5_archive() -> bytes:
    magic = b"Rar!\x1a\x07\x01\x00"
    main = _rar5_block(1, b"\x00")
    name = b"empty.txt"
    file_fields = b"\x00\x00\x00\x00\x00" + bytes([len(name)]) + name
    file_block = _rar5_block(2, file_fields)
    service_name = b"CMT"
    service_fields = b"\x00\x00\x00\x00\x00" + bytes([len(service_name)]) + service_name
    service = _rar5_block(3, service_fields)
    end = _rar5_block(5, b"\x00")
    return magic + main + file_block + service + end


def _rar5_block(block_type: int, fields: bytes) -> bytes:
    header = bytes([block_type, 0]) + fields
    encoded_size = _vint(len(header))
    crc_data = encoded_size + header
    return struct.pack("<I", zlib.crc32(crc_data) & 0xFFFFFFFF) + crc_data


def _vint(value: int) -> bytes:
    output = bytearray()
    while True:
        byte = value & 0x7F; value >>= 7
        output.append(byte | (0x80 if value else 0))
        if not value: return bytes(output)


def _rar_blocks(data: bytes) -> list[tuple[int, int, int]]:
    output=[]; pos=8
    while pos + 6 <= len(data):
        size=data[pos+4]; start=pos+5; block_type=data[start]; end=start+size
        if end > len(data): break
        output.append((block_type,pos,end)); pos=end
    return output


def _rar_block_offset(data: bytes, block_type: int) -> int:
    return next(pos for kind, pos, _ in _rar_blocks(data) if kind == block_type)


def _rar_drop_end(data: bytes) -> bytes:
    return data[:next(pos for kind,pos,_ in _rar_blocks(data) if kind == 5)]


def _tar_archive(payload: bytes, profile: str) -> bytes:
    buffer=io.BytesIO(); mode=tarfile.GNU_FORMAT if profile == "gnu_longname" else tarfile.PAX_FORMAT
    with tarfile.open(fileobj=buffer, mode="w", format=mode) as archive:
        name=("long/" * 40 + "payload.txt") if profile in {"pax_header","gnu_longname"} else "payload.txt"
        info=tarfile.TarInfo(name); info.size=len(payload); archive.addfile(info,io.BytesIO(payload))
    data=bytearray(buffer.getvalue())
    if profile == "sparse_header":
        data[156]=ord("S"); _fix_tar_checksum(data,0)
    return bytes(data)


def _tar_entries(data: bytes):
    pos=0
    while pos+512<=len(data) and any(data[pos:pos+512]):
        raw=data[pos+124:pos+136].rstrip(b"\0 ").strip() or b"0"
        try: size=int(raw,8)
        except ValueError: return
        end=pos+512+((size+511)//512)*512
        yield pos,end,data[pos+156],size
        pos=end


def _tar_corrupt_pax(data: bytes) -> bytes:
    for pos,_,kind,size in _tar_entries(data):
        if kind in (ord("x"),ord("g")) and size:
            return _replace(data,pos+512,b"X")
    return _flip(data,148)


def _tar_corrupt_longname(data: bytes) -> bytes:
    for pos,_,kind,size in _tar_entries(data):
        if kind in (ord("L"),ord("K")) and size:
            return _replace(data,pos+512+size-1,b"X")
    return _flip(data,148)


def _tar_corrupt_sparse(data: bytes) -> bytes:
    for pos,_,kind,_ in _tar_entries(data):
        if kind == ord("S"): return _replace(data,pos+148,b"000000\0 ")
    return _flip(data,148)


def _fix_tar_checksum(data: bytearray, offset: int) -> None:
    header=bytearray(data[offset:offset+512]); header[148:156]=b" "*8
    data[offset+148:offset+156]=f"{sum(header):06o}\0 ".encode()


def _gzip_with_fhcrc(payload: bytes) -> bytes:
    raw=gzip.compress(payload); header=bytearray(raw[:10]); header[3]|=0x02
    return bytes(header)+struct.pack("<H",zlib.crc32(header)&0xFFFF)+raw[10:]


def _replace(data: bytes, offset: int, value: bytes) -> bytes:
    output=bytearray(data); output[offset:offset+len(value)]=value; return bytes(output)


def _flip(data: bytes, offset: int) -> bytes:
    output=bytearray(data); output[offset]^=0x5A; return bytes(output)


def _extension(format_name: str) -> str:
    return {"gzip":"gz","bzip2":"bz2","zstd":"zst"}.get(format_name,format_name)


def _input_size(record: dict[str, Any]) -> int:
    path=Path(str((record.get("damaged_input") or {}).get("path") or ""))
    return path.stat().st_size if path.is_file() else 0
