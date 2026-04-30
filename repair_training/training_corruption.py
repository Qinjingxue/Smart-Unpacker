from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import random
import struct
import subprocess
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import PatchOperation, PatchPlan


ArchiveFormat = Literal["zip", "tar", "gzip", "bzip2", "xz", "zstd", "7z", "rar", "tar.gz", "tar.bz2", "tar.xz", "tar.zst"]


MATERIAL_FORMAT_DIRS = (
    "zip",
    "7z",
    "rar",
    "tar",
    "gzip",
    "bzip2",
    "xz",
    "zstd",
    "tar_gz",
    "tar_bz2",
    "tar_xz",
    "tar_zst",
)


MATERIAL_FORMAT_ALIASES = {
    "zip": "zip",
    "7z": "7z",
    "rar": "rar",
    "tar": "tar",
    "gzip": "gzip",
    "gz": "gzip",
    "bzip2": "bzip2",
    "bz2": "bzip2",
    "xz": "xz",
    "zstd": "zstd",
    "zst": "zstd",
    "tar_gz": "tar.gz",
    "tar.gz": "tar.gz",
    "tgz": "tar.gz",
    "tar_bz2": "tar.bz2",
    "tar.bz2": "tar.bz2",
    "tbz": "tar.bz2",
    "tbz2": "tar.bz2",
    "tar_xz": "tar.xz",
    "tar.xz": "tar.xz",
    "txz": "tar.xz",
    "tar_zst": "tar.zst",
    "tar.zst": "tar.zst",
    "tar.zstd": "tar.zst",
    "tzst": "tar.zst",
}


@dataclass(frozen=True)
class BinaryMutation:
    name: str
    operation: PatchOperation
    zone: str = ""
    expected_effect: str = ""

    def to_dict(self) -> dict:
        operation = self.operation.to_dict()
        payload = {
            "name": self.name,
            "kind": _mutation_kind(self.name, self.operation.op),
            "zone": self.zone,
            "offset": self.operation.offset,
            "size": self.operation.size,
            "operation": operation,
        }
        if self.expected_effect:
            payload["expected_effect"] = self.expected_effect
        return payload


@dataclass(frozen=True)
class CorruptionCase:
    case_id: str
    format: ArchiveFormat
    seed: int
    source_input: dict
    clean_source_input: dict
    clean_data: bytes
    corrupted_data: bytes
    mutations: list[BinaryMutation]
    damage_flags: list[str]
    expected_statuses: tuple[str, ...]
    expected_module: str = ""
    expected_files: dict[str, bytes] = field(default_factory=dict)
    expected_payload: bytes = b""
    expected_bytes: bytes = b""
    output_required: bool = True
    builder_call: str = ""
    password: str | None = None

    @property
    def patch_plan(self) -> PatchPlan:
        return PatchPlan(
            operations=[mutation.operation for mutation in self.mutations],
            provenance={
                "case_id": self.case_id,
                "format": self.format,
                "seed": self.seed,
                "mutations": [mutation.to_dict() for mutation in self.mutations],
            },
            confidence=0.5,
        )

    @property
    def corrupted_sha256(self) -> str:
        return hashlib.sha256(self.corrupted_data).hexdigest()

    def mutation_summary(self) -> list[dict]:
        return [mutation.to_dict() for mutation in self.mutations]

    def diagnostic_report(self, repair_result: Any = None) -> dict:
        report = {
            "seed": self.seed,
            "case_id": self.case_id,
            "format": self.format,
            "corrupted_sha256": self.corrupted_sha256,
            "source_input": _source_input_summary(self.source_input),
            "clean_source_input": _source_input_summary(self.clean_source_input),
            "damage_flags": list(self.damage_flags),
            "oracle": {
                "expected_statuses": list(self.expected_statuses),
                "expected_module": self.expected_module,
                "output_required": self.output_required,
                "expected_files": sorted(self.expected_files),
                "expected_payload_bytes": len(self.expected_payload),
                "expected_bytes": len(self.expected_bytes),
                "password_present": self.password is not None,
            },
            "mutations": self.mutation_summary(),
            "patch_plan": self.patch_plan.to_dict(),
            "regression_snippet": self.regression_snippet(),
        }
        if repair_result is not None:
            report["repair_result"] = repair_result_summary(repair_result)
        return report

    def diagnostic_json(self, repair_result: Any = None) -> str:
        return json.dumps(self.diagnostic_report(repair_result), ensure_ascii=True, indent=2, sort_keys=True)

    def corpus_manifest_record(
        self,
        *,
        source_archive_id: str,
        source_path: str,
        damage_profile: str,
        variant_index: int,
        material_format: str = "",
        material_sample_id: str = "",
        damage_json_path: str = "",
    ) -> dict[str, Any]:
        damaged_path = str(self.source_input.get("path") or "")
        return {
            "schema_version": 1,
            "sample_id": self.case_id,
            "query_id": f"{self.case_id}:0",
            "source_archive_id": source_archive_id,
            "source_path": source_path,
            "source_archive_name": Path(source_path).name,
            "damaged_path": damaged_path,
            "damaged_file_name": Path(damaged_path).name if damaged_path else "",
            "damage_json_path": damage_json_path,
            "material_format": material_format,
            "material_sample_id": material_sample_id,
            "format": self.format,
            "seed": self.seed,
            "variant_index": int(variant_index),
            "damage_profile": damage_profile,
            "clean_sha256": hashlib.sha256(self.clean_data).hexdigest(),
            "corrupted_sha256": self.corrupted_sha256,
            "clean_input": _source_input_summary(self.clean_source_input),
            "damaged_input": dict(self.source_input),
            "corruption_plan": self.mutation_summary(),
            "damage_flags": list(self.damage_flags),
            "oracle": self.oracle_manifest(),
        }

    def oracle_manifest(self) -> dict[str, Any]:
        return {
            "expected_statuses": list(self.expected_statuses),
            "expected_module": self.expected_module,
            "output_required": self.output_required,
            "expected_files": {
                name: {
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
                for name, payload in sorted(self.expected_files.items())
            },
            "expected_payload": {
                "size": len(self.expected_payload),
                "sha256": hashlib.sha256(self.expected_payload).hexdigest(),
            } if self.expected_payload else {},
            "expected_bytes": {
                "size": len(self.expected_bytes),
                "sha256": hashlib.sha256(self.expected_bytes).hexdigest(),
            } if self.expected_bytes else {},
        }

    def regression_snippet(self, root_expr: str = "tmp_path / \"case\"") -> str:
        builder = self.builder_call or f"{self.case_id}(root)"
        return "\n".join([
            "from repair_training.training_corruption import BinaryCorruptor, apply_mutations",
            "",
            f"root = {root_expr}",
            f"case = BinaryCorruptor({self.seed}).{builder}",
            f"assert case.case_id == {self.case_id!r}",
            f"assert case.corrupted_sha256 == {self.corrupted_sha256!r}",
            "assert apply_mutations(case.clean_data, case.mutations) == case.corrupted_data",
        ])

    def archive_state_input(self):
        descriptor = ArchiveInputDescriptor.from_any(
            self.clean_source_input,
            archive_path=str(self.clean_source_input.get("path") or self.clean_source_input.get("archive_path") or ""),
            part_paths=[
                str(item.get("path") or "")
                for item in self.clean_source_input.get("ranges", [])
                if isinstance(item, dict) and item.get("path")
            ] or None,
            format_hint=self.format,
        )
        from sunpack.contracts.archive_state import ArchiveState

        return ArchiveState.from_archive_input(descriptor, patches=[self.patch_plan])


class BinaryCorruptor:
    def __init__(self, seed: int):
        self.seed = int(seed)
        self.random = random.Random(self.seed)

    def zip_missing_cd_payload_bad_tail(self, root: Path) -> CorruptionCase:
        entries = {
            "bad.bin": _pseudo_random_payload(self.seed + 1, 96),
            "good.txt": b"good zip payload",
            "keep.bin": _pseudo_random_payload(self.seed + 2, 80),
        }
        clean = _zip_bytes(entries)
        bad_offset = _zip_payload_offset(clean, "bad.bin")
        flip_at = bad_offset + self.random.randrange(0, len(entries["bad.bin"]))
        cd_offset = _zip_cd_offset(clean)
        tail = self._junk("ZIP-JUNK", 8, 24)
        mutations = [
            _replace_byte("flip_zip_payload_byte", flip_at, clean[flip_at] ^ 0x55, "zip.local_payload", "one entry CRC fails"),
            _truncate("drop_zip_central_directory", cd_offset, "zip.central_directory", "local headers must drive recovery"),
            _append("append_zip_tail_noise", tail, "archive.tail", "boundary repair sees trailing noise"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "zip-missing-cd-payload-tail.zip",
            "zip_missing_cd_payload_bad_tail",
            "zip",
            clean,
            corrupted,
            mutations,
            damage_flags=[
                "central_directory_bad",
                "local_header_recovery",
                "checksum_error",
                "crc_error",
                "damaged",
                "trailing_junk",
            ],
            expected_statuses=("partial",),
            expected_module="zip_central_directory_rebuild",
            expected_files={
                "good.txt": entries["good.txt"],
                "keep.bin": entries["keep.bin"],
            },
        )

    def zip_eocd_multi_field_tail(self, root: Path) -> CorruptionCase:
        entries = {
            "alpha.txt": b"alpha zip payload",
            "bravo.bin": _pseudo_random_payload(self.seed + 5, 72),
        }
        clean = _zip_bytes(entries)
        eocd = _zip_eocd_offset(clean)
        tail = self._junk("ZIP-EOCD-JUNK", 6, 18)
        mutations = [
            _replace_bytes("bad_zip_eocd_counts", eocd + 8, struct.pack("<HH", 1, 1), "zip.eocd.entry_counts", "directory counts must be recomputed"),
            _replace_bytes("bad_zip_eocd_cd_offset", eocd + 16, struct.pack("<I", 0), "zip.eocd.cd_offset", "central directory offset must be rebuilt"),
            _replace_bytes("bad_zip_eocd_comment_length", eocd + 20, struct.pack("<H", 0), "zip.eocd.comment_length", "comment/tail boundary must be normalized"),
            _append("append_zip_eocd_tail_noise", tail, "archive.tail", "EOCD repair must ignore trailing bytes"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "zip-eocd-fields-tail.zip",
            "zip_eocd_multi_field_tail",
            "zip",
            clean,
            corrupted,
            mutations,
            damage_flags=[
                "central_directory_offset_bad",
                "central_directory_count_bad",
                "comment_length_bad",
                "trailing_junk",
                "central_directory_bad",
            ],
            expected_statuses=("repaired",),
            expected_module="zip_eocd_repair",
            expected_files=entries,
        )

    def zip_combo_directory_payload_raw_noise(self, root: Path) -> CorruptionCase:
        entries = {
            "bad.bin": _pseudo_random_payload(self.seed + 9, 96),
            "good.txt": b"good zip combo payload",
            "keep.bin": _pseudo_random_payload(self.seed + 10, 80),
        }
        clean = _zip_bytes(entries)
        eocd = _zip_eocd_offset(clean)
        cd_offset = _zip_cd_offset(clean)
        bad_offset = _zip_payload_offset(clean, "bad.bin")
        flip_at = bad_offset + self.random.randrange(0, len(entries["bad.bin"]))
        mutations = self.combine_mutations(
            [
                _replace_byte("combo_flip_zip_payload_byte", flip_at, clean[flip_at] ^ 0x33, "zip.local_payload", "one entry CRC fails"),
            ],
            [
                _replace_bytes("combo_bad_zip_eocd_counts", eocd + 8, struct.pack("<HH", 1, 1), "zip.eocd.entry_counts", "directory counts must be recomputed"),
                _replace_bytes("combo_bad_zip_eocd_cd_offset", eocd + 16, struct.pack("<I", 0), "zip.eocd.cd_offset", "central directory offset must be rebuilt"),
            ],
            [
                _insert("combo_insert_raw_cd_noise", cd_offset, self._junk("RAW-CD", 4, 12), "raw.insert.central_directory", "central directory has inserted noise"),
                _append("combo_append_zip_tail_noise", self._junk("ZIP-COMBO", 8, 20), "archive.tail", "boundary repair sees trailing noise"),
            ],
        )
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "zip-combo-directory-payload-raw.zip",
            "zip_combo_directory_payload_raw_noise",
            "zip",
            clean,
            corrupted,
            mutations,
            damage_flags=[
                "central_directory_offset_bad",
                "central_directory_count_bad",
                "central_directory_bad",
                "local_header_recovery",
                "checksum_error",
                "crc_error",
                "damaged",
                "trailing_junk",
                "boundary_unreliable",
            ],
            expected_statuses=("partial", "repaired"),
            expected_module="zip_central_directory_rebuild",
            expected_files={
                "good.txt": entries["good.txt"],
                "keep.bin": entries["keep.bin"],
            },
            output_required=False,
        )

    def tar_header_checksum_tail(self, root: Path) -> CorruptionCase:
        entries = {
            "alpha.txt": b"alpha tar payload",
            "beta.bin": _pseudo_random_payload(self.seed + 3, 128),
        }
        clean = _tar_bytes(entries)
        tail = self._junk("TAR-JUNK", 4, 16)
        mutations = [
            _replace_bytes("zero_tar_header_checksum", 148, b"000000\0 ", "tar.header.checksum", "header checksum must be recomputed"),
            _append("append_tar_tail_noise", tail, "archive.tail", "zero-block boundary has trailing noise"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "tar-checksum-tail.tar",
            "tar_header_checksum_tail",
            "tar",
            clean,
            corrupted,
            mutations,
            damage_flags=["tar_checksum_bad", "trailing_junk", "boundary_unreliable"],
            expected_statuses=("repaired",),
            expected_module="tar_header_checksum_fix",
            expected_files=entries,
        )

    def tar_checksum_missing_zero_blocks(self, root: Path) -> CorruptionCase:
        entries = {
            "alpha.txt": b"alpha tar payload",
            "beta.bin": _pseudo_random_payload(self.seed + 6, 96),
        }
        clean = _tar_bytes(entries)
        payload_end = _tar_payload_end(clean, entries)
        mutations = [
            _replace_bytes("zero_tar_header_checksum", 148, b"000000\0 ", "tar.header.checksum", "header checksum must be recomputed"),
            _truncate("drop_tar_zero_blocks", payload_end, "tar.trailing_zero_blocks", "zero blocks must be restored in a later round"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "tar-checksum-missing-zero.tar",
            "tar_checksum_missing_zero_blocks",
            "tar",
            clean,
            corrupted,
            mutations,
            damage_flags=["tar_checksum_bad", "missing_end_block", "probably_truncated"],
            expected_statuses=("repaired",),
            expected_module="tar_header_checksum_fix",
            expected_files=entries,
        )

    def tar_combo_checksum_missing_zero_raw_tail(self, root: Path) -> CorruptionCase:
        entries = {
            "alpha.txt": b"alpha tar combo payload",
            "beta.bin": _pseudo_random_payload(self.seed + 11, 128),
        }
        clean = _tar_bytes(entries)
        payload_end = _tar_payload_end(clean, entries)
        mutations = self.combine_mutations(
            [
                _replace_bytes("combo_zero_tar_header_checksum", 148, b"000000\0 ", "tar.header.checksum", "header checksum must be recomputed"),
            ],
            [
                _truncate("combo_drop_tar_zero_blocks", payload_end, "tar.trailing_zero_blocks", "zero blocks must be restored in a later round"),
            ],
            [
                _append("combo_append_tar_raw_tail", self._junk("RAW-TAR", 4, 16), "raw.append.tail", "raw bytes after truncated tar payload"),
            ],
        )
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "tar-combo-checksum-zero-tail.tar",
            "tar_combo_checksum_missing_zero_raw_tail",
            "tar",
            clean,
            corrupted,
            mutations,
            damage_flags=[
                "tar_checksum_bad",
                "missing_end_block",
                "probably_truncated",
                "trailing_junk",
                "boundary_unreliable",
            ],
            expected_statuses=("repaired",),
            expected_module="tar_header_checksum_fix",
            expected_files=entries,
        )

    def gzip_footer_bad_tail(self, root: Path) -> CorruptionCase:
        payload = b"gzip random corruption payload" + _pseudo_random_payload(self.seed + 4, 64)
        clean = gzip.compress(payload)
        tail = self._junk("GZIP-JUNK", 5, 18)
        mutations = [
            _replace_bytes("zero_gzip_footer", len(clean) - 8, b"\0" * 8, "gzip.footer", "CRC and ISIZE must be rewritten"),
            _append("append_gzip_tail_noise", tail, "archive.tail", "footer repair must ignore extra bytes"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "gzip-footer-tail.gz",
            "gzip_footer_bad_tail",
            "gzip",
            clean,
            corrupted,
            mutations,
            damage_flags=["gzip_footer_bad", "checksum_error", "trailing_junk"],
            expected_statuses=("repaired",),
            expected_module="gzip_footer_fix",
            expected_payload=payload,
        )

    def gzip_combo_footer_insert_tail(self, root: Path) -> CorruptionCase:
        payload = b"gzip combo corruption payload" + _pseudo_random_payload(self.seed + 12, 64)
        clean = gzip.compress(payload)
        mutations = self.combine_mutations(
            [
                _replace_bytes("combo_zero_gzip_footer", len(clean) - 8, b"\0" * 8, "gzip.footer", "CRC and ISIZE must be rewritten"),
            ],
            [
                _insert("combo_insert_raw_before_footer", len(clean) - 8, self._junk("RAW-GZ", 3, 9), "raw.insert.before_footer", "raw bytes appear between deflate stream and footer"),
                _append("combo_append_gzip_tail_noise", self._junk("GZIP-COMBO", 5, 18), "archive.tail", "footer repair must ignore extra bytes"),
            ],
        )
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "gzip-combo-footer-insert-tail.gz",
            "gzip_combo_footer_insert_tail",
            "gzip",
            clean,
            corrupted,
            mutations,
            damage_flags=["gzip_footer_bad", "checksum_error", "trailing_junk", "boundary_unreliable"],
            expected_statuses=("repaired",),
            expected_module="gzip_footer_fix",
            expected_payload=payload,
        )

    def bzip2_trailing_junk(self, root: Path) -> CorruptionCase:
        payload = b"bzip2 random corruption payload" + _pseudo_random_payload(self.seed + 7, 64)
        clean = bz2.compress(payload)
        tail = self._junk("BZ2-JUNK", 5, 16)
        mutations = [
            _append("append_bzip2_tail_noise", tail, "archive.tail", "stream boundary must be trimmed"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "bzip2-tail.bz2",
            "bzip2_trailing_junk",
            "bzip2",
            clean,
            corrupted,
            mutations,
            damage_flags=["trailing_junk"],
            expected_statuses=("repaired",),
            expected_module="bzip2_trailing_junk_trim",
            expected_payload=payload,
        )

    def xz_trailing_junk(self, root: Path) -> CorruptionCase:
        payload = b"xz random corruption payload" + _pseudo_random_payload(self.seed + 8, 64)
        clean = lzma.compress(payload, format=lzma.FORMAT_XZ)
        tail = self._junk("XZ-JUNK", 5, 16)
        mutations = [
            _append("append_xz_tail_noise", tail, "archive.tail", "stream boundary must be trimmed"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "xz-tail.xz",
            "xz_trailing_junk",
            "xz",
            clean,
            corrupted,
            mutations,
            damage_flags=["trailing_junk"],
            expected_statuses=("repaired",),
            expected_module="xz_trailing_junk_trim",
            expected_payload=payload,
        )

    def seven_zip_start_next_crc_tail(self, root: Path) -> CorruptionCase:
        clean = _seven_zip_bytes(minor=3, next_header=b"\x01\x02")
        start_header = bytearray(clean[12:32])
        start_header[16:20] = struct.pack("<I", 0)
        bad_start_crc = struct.pack("<I", zlib_crc32(start_header))
        mutations = [
            _replace_bytes("bad_7z_start_crc", 8, b"\0\0\0\0", "7z.start_header_crc", "start header CRC must be recomputed"),
            _replace_bytes("bad_7z_next_crc", 28, b"\0\0\0\0", "7z.next_header_crc", "next header CRC must be rewritten"),
            _replace_bytes("sync_7z_start_crc_to_bad_header", 8, bad_start_crc, "7z.start_header_crc", "start CRC tracks the intentionally bad next CRC"),
            _append("append_7z_crc_tail_noise", self._junk("7Z-JUNK", 4, 12), "archive.tail", "CRC repair must preserve logical stream"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "seven-crc-tail.7z",
            "seven_zip_start_next_crc_tail",
            "7z",
            clean,
            corrupted,
            mutations,
            damage_flags=["start_header_crc_bad", "next_header_crc_bad", "trailing_junk"],
            expected_statuses=("repaired",),
            expected_module="seven_zip_crc_field_repair",
            expected_bytes=clean,
        )

    def seven_zip_fake_magic_sfx(self, root: Path) -> CorruptionCase:
        clean = _seven_zip_bytes()
        prefix = b"MZ-FAKE-7Z" + b"7z\xbc\xaf\x27\x1c" + b"\xff\xffNOT-A-HEADER" + self._junk("SFX", 3, 8)
        mutations = [
            _insert("insert_fake_7z_sfx_prefix", 0, prefix, "7z.sfx.fake_magic", "boundary repair must ignore fake 7z magic"),
            _append("append_7z_sfx_tail", self._junk("7Z-SFX", 4, 10), "archive.tail", "boundary repair must crop tail"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "seven-fake-sfx.exe",
            "seven_zip_fake_magic_sfx",
            "7z",
            clean,
            corrupted,
            mutations,
            damage_flags=["carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"],
            expected_statuses=("repaired",),
            expected_module="seven_zip_precise_boundary_repair",
            expected_bytes=clean,
        )

    def rar5_sfx_missing_end_tail(self, root: Path) -> CorruptionCase:
        clean = _rar5_bytes(file_payload=b"rar payload")
        without_end = RAR5_MAGIC + _rar5_block(1) + _rar5_block(2, data=b"rar payload")
        prefix = b"MZ-RAR-SFX" + self._junk("RAR", 4, 10)
        tail = self._junk("RAR-TAIL", 4, 10)
        mutations = [
            _truncate("drop_rar5_end_block", len(without_end), "rar.end_block", "end block must be restored"),
            _insert("insert_rar5_sfx_prefix", 0, prefix, "rar.sfx.prefix", "carrier crop must find real RAR"),
            _append("append_rar5_tail_noise", tail, "archive.tail", "tail should be trimmed after carrier crop"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "rar5-sfx-missing-end.exe",
            "rar5_sfx_missing_end_tail",
            "rar",
            clean,
            corrupted,
            mutations,
            damage_flags=["carrier_archive", "sfx", "boundary_unreliable", "trailing_junk"],
            expected_statuses=("repaired",),
            expected_module="rar_carrier_crop_deep_recovery",
            expected_bytes=without_end,
        )

    def raw_binary_perturbation(self, root: Path, fmt: ArchiveFormat = "zip", *, budget: int = 5) -> CorruptionCase:
        clean = _clean_archive_bytes(fmt, self.seed)
        mutations = self.raw_binary_mutations(clean, budget=budget, label_prefix=f"raw_{fmt}")
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            f"raw-{fmt}-perturbed.{_extension_for_format(fmt)}",
            f"raw_{fmt}_binary_perturbation",
            fmt,
            clean,
            corrupted,
            mutations,
            damage_flags=["damaged", "checksum_error", "boundary_unreliable"],
            expected_statuses=("repaired", "partial", "unrepairable", "unsupported"),
            output_required=False,
            builder_call=f'raw_binary_perturbation(root, "{fmt}", budget={budget})',
        )

    def zone_aware_raw_perturbation(self, root: Path, fmt: ArchiveFormat = "zip") -> CorruptionCase:
        clean = _clean_archive_bytes(fmt, self.seed)
        mutations = self.zone_aware_raw_mutations(clean, fmt=fmt)
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            f"zone-{fmt}-perturbed.{_extension_for_format(fmt)}",
            f"zone_{fmt}_raw_perturbation",
            fmt,
            clean,
            corrupted,
            mutations,
            damage_flags=["damaged", "checksum_error", "boundary_unreliable"],
            expected_statuses=("repaired", "partial", "unrepairable", "unsupported"),
            output_required=False,
            builder_call=f'zone_aware_raw_perturbation(root, "{fmt}")',
        )

    def encrypted_zip_trailing_junk(self, root: Path, *, password: str = "secret") -> CorruptionCase:
        clean = _build_encrypted_zip(root, password=password)
        tail = self._junk("ENC-ZIP-JUNK", 5, 15)
        mutations = [
            _append("append_encrypted_zip_tail_noise", tail, "zip.encrypted.tail", "encrypted archive should still be structurally repairable with password"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "encrypted-tail.zip",
            "encrypted_zip_trailing_junk",
            "zip",
            clean,
            corrupted,
            mutations,
            damage_flags=["trailing_junk"],
            expected_statuses=("repaired",),
            expected_module="zip_trailing_junk_trim",
            output_required=False,
            password=password,
            builder_call=f'encrypted_zip_trailing_junk(root, password="{password}")',
        )

    def encrypted_zip_payload_bad_unknown_password(self, root: Path, *, password: str = "secret") -> CorruptionCase:
        clean = _build_encrypted_zip(root, password=password)
        payload_offset = max(0, len(clean) // 2)
        mutations = [
            _replace_byte("flip_encrypted_zip_payload_byte", payload_offset, clean[payload_offset] ^ 0x44, "zip.encrypted.payload", "without password this must not be misreported as repaired"),
        ]
        corrupted = apply_mutations(clean, mutations)
        return self._write_case(
            root,
            "encrypted-payload-bad.zip",
            "encrypted_zip_payload_bad_unknown_password",
            "zip",
            clean,
            corrupted,
            mutations,
            damage_flags=["checksum_error", "crc_error", "damaged"],
            expected_statuses=("needs_password", "unrepairable", "unsupported"),
            output_required=False,
            builder_call=f'encrypted_zip_payload_bad_unknown_password(root, password="{password}")',
        )

    def zip_multipart_tail_noise(self, root: Path) -> CorruptionCase:
        entries = {
            "alpha.txt": b"alpha multipart zip payload",
            "bravo.bin": _pseudo_random_payload(self.seed + 13, 96),
        }
        clean = _zip_bytes(entries)
        tail = self._junk("ZIP-PART-TAIL", 8, 20)
        mutations = [
            _append("append_zip_part_tail_noise", tail, "multipart.tail", "tail noise is attached to the last logical part"),
        ]
        corrupted = apply_mutations(clean, mutations)
        source_input, clean_source_input = self._write_multipart_case(root, "zip-multipart-tail", "zip", clean, corrupted, split_points=[len(clean) // 2])
        return CorruptionCase(
            case_id="zip_multipart_tail_noise",
            format="zip",
            seed=self.seed,
            source_input=source_input,
            clean_source_input=clean_source_input,
            clean_data=clean,
            corrupted_data=corrupted,
            mutations=mutations,
            damage_flags=["trailing_junk", "boundary_unreliable"],
            expected_statuses=("repaired",),
            expected_module="zip_trailing_junk_trim",
            expected_files=entries,
            builder_call="zip_multipart_tail_noise(root)",
        )

    def zip_multipart_missing_middle(self, root: Path) -> CorruptionCase:
        entries = {
            "alpha.txt": b"alpha multipart zip payload",
            "bravo.bin": _pseudo_random_payload(self.seed + 14, 256),
            "charlie.txt": b"charlie payload",
        }
        clean = _zip_bytes(entries)
        start = max(8, len(clean) // 3)
        size = max(8, len(clean) // 5)
        mutations = [
            _delete("delete_zip_middle_part", start, size, "multipart.missing_middle", "middle volume bytes are missing"),
            _append("append_zip_missing_middle_noise", self._junk("ZIP-MISSING", 4, 12), "multipart.tail", "remaining part has trailing noise"),
        ]
        corrupted = apply_mutations(clean, mutations)
        source_input, clean_source_input = self._write_multipart_case(root, "zip-multipart-missing", "zip", clean, corrupted, split_points=[start])
        return CorruptionCase(
            case_id="zip_multipart_missing_middle",
            format="zip",
            seed=self.seed,
            source_input=source_input,
            clean_source_input=clean_source_input,
            clean_data=clean,
            corrupted_data=corrupted,
            mutations=mutations,
            damage_flags=["missing_volume", "input_truncated", "central_directory_bad", "checksum_error", "trailing_junk"],
            expected_statuses=("unrepairable", "unsupported"),
            output_required=False,
            builder_call="zip_multipart_missing_middle(root)",
        )

    def raw_binary_mutations(self, data: bytes, *, budget: int, label_prefix: str = "raw") -> list[BinaryMutation]:
        if not data:
            return []
        output: list[BinaryMutation] = []
        for index in range(max(0, int(budget))):
            op = self.random.choice(["flip", "zero", "insert", "delete", "truncate"])
            if op == "flip":
                offset = self.random.randrange(0, len(data))
                output.append(_replace_byte(f"{label_prefix}_flip_byte_{index}", offset, data[offset] ^ (1 << self.random.randrange(0, 8)), "raw.byte", "arbitrary byte changed"))
            elif op == "zero":
                offset, size = self._bounded_range(len(data), 1, 16)
                output.append(_replace_bytes(f"{label_prefix}_zero_range_{index}", offset, b"\0" * size, "raw.range", "arbitrary range zeroed"))
            elif op == "insert":
                offset = self.random.randrange(0, len(data) + 1)
                output.append(_insert(f"{label_prefix}_insert_junk_{index}", offset, self._junk("RAW", 1, 12), "raw.insert", "arbitrary bytes inserted"))
            elif op == "delete":
                offset, size = self._bounded_range(len(data), 1, 12)
                output.append(_delete(f"{label_prefix}_delete_range_{index}", offset, size, "raw.delete", "arbitrary bytes deleted"))
            elif len(data) > 8:
                min_offset = max(1, len(data) // 3)
                offset = self.random.randrange(min_offset, len(data))
                output.append(_truncate(f"{label_prefix}_truncate_tail_{index}", offset, "raw.truncate", "arbitrary tail truncated"))
        return output

    def zone_aware_raw_mutations(self, data: bytes, *, fmt: ArchiveFormat) -> list[BinaryMutation]:
        zones = _semantic_zones(data, fmt)
        output: list[BinaryMutation] = []
        for zone_name in ("header", "payload", "footer", "boundary"):
            start, end = zones[zone_name]
            if end <= start:
                continue
            offset = self.random.randrange(start, end)
            output.append(_replace_byte(f"zone_{fmt}_{zone_name}_flip", offset, data[offset] ^ 0x21, f"{fmt}.{zone_name}", f"{zone_name} byte changed"))
        fake_magic = _fake_magic_for_format(fmt)
        insert_at = zones["boundary"][0]
        if fake_magic:
            output.append(_insert(f"zone_{fmt}_insert_fake_magic", insert_at, fake_magic + self._junk("FAKE", 2, 6), f"{fmt}.boundary.fake_magic", "fake archive magic inserted at semantic boundary"))
        return output

    def combine_mutations(self, *groups: list[BinaryMutation]) -> list[BinaryMutation]:
        combined: list[BinaryMutation] = []
        for group_index, group in enumerate(groups):
            for mutation_index, mutation in enumerate(group):
                combined.append(_tag_combined_mutation(mutation, group_index, mutation_index))
        return combined

    def build_default_cases(self, root: Path) -> list[CorruptionCase]:
        return [
            self.zip_missing_cd_payload_bad_tail(root / "zip"),
            self.zip_eocd_multi_field_tail(root / "zip_eocd"),
            self.zip_combo_directory_payload_raw_noise(root / "zip_combo"),
            self.tar_header_checksum_tail(root / "tar"),
            self.tar_checksum_missing_zero_blocks(root / "tar_missing_zero"),
            self.tar_combo_checksum_missing_zero_raw_tail(root / "tar_combo"),
            self.gzip_footer_bad_tail(root / "gzip"),
            self.gzip_combo_footer_insert_tail(root / "gzip_combo"),
            self.bzip2_trailing_junk(root / "bzip2"),
            self.xz_trailing_junk(root / "xz"),
            self.zip_multipart_tail_noise(root / "zip_multipart_tail"),
            self.zip_multipart_missing_middle(root / "zip_multipart_missing"),
            self.seven_zip_start_next_crc_tail(root / "7z_crc"),
            self.seven_zip_fake_magic_sfx(root / "7z_sfx"),
            self.rar5_sfx_missing_end_tail(root / "rar_sfx"),
        ]

    def _junk(self, prefix: str, min_len: int, max_len: int) -> bytes:
        size = self.random.randrange(min_len, max_len + 1)
        return prefix.encode("ascii") + self.random.randbytes(size)

    def _bounded_range(self, total_size: int, min_len: int, max_len: int) -> tuple[int, int]:
        if total_size <= 1:
            return 0, total_size
        size = self.random.randrange(min_len, min(max_len, total_size) + 1)
        offset = self.random.randrange(0, max(1, total_size - size + 1))
        return offset, size

    def _write_case(
        self,
        root: Path,
        filename: str,
        case_id: str,
        fmt: ArchiveFormat,
        clean: bytes,
        corrupted: bytes,
        mutations: list[BinaryMutation],
        *,
        damage_flags: list[str],
        expected_statuses: tuple[str, ...],
        expected_module: str = "",
        expected_files: dict[str, bytes] | None = None,
        expected_payload: bytes = b"",
        expected_bytes: bytes = b"",
        output_required: bool = True,
        builder_call: str = "",
        password: str | None = None,
    ) -> CorruptionCase:
        root.mkdir(parents=True, exist_ok=True)
        clean_path = root / f"clean-{filename}"
        clean_path.write_bytes(clean)
        path = root / filename
        path.write_bytes(corrupted)
        return CorruptionCase(
            case_id=case_id,
            format=fmt,
            seed=self.seed,
            source_input={"kind": "file", "path": str(path), "format_hint": fmt},
            clean_source_input={"kind": "file", "path": str(clean_path), "format_hint": fmt},
            clean_data=clean,
            corrupted_data=corrupted,
            mutations=list(mutations),
            damage_flags=list(damage_flags),
            expected_statuses=expected_statuses,
            expected_module=expected_module,
            expected_files=dict(expected_files or {}),
            expected_payload=expected_payload,
            expected_bytes=expected_bytes,
            output_required=output_required,
            builder_call=builder_call or f"{case_id}(root)",
            password=password,
        )

    def _write_multipart_case(
        self,
        root: Path,
        stem: str,
        fmt: ArchiveFormat,
        clean: bytes,
        corrupted: bytes,
        *,
        split_points: list[int],
    ) -> tuple[dict, dict]:
        root.mkdir(parents=True, exist_ok=True)
        corrupted_ranges = _write_split_ranges(root, stem, corrupted, split_points)
        clean_ranges = _write_split_ranges(root, f"clean-{stem}", clean, split_points)
        return (
            {"kind": "concat_ranges", "ranges": corrupted_ranges, "format_hint": fmt},
            {"kind": "concat_ranges", "ranges": clean_ranges, "format_hint": fmt},
        )


def detect_archive_format(path: Path) -> ArchiveFormat | None:
    lower = path.name.lower()
    if lower.endswith(".zip"):
        return "zip"
    if lower.endswith(".tar"):
        return "tar"
    if lower.endswith((".tar.gz", ".tgz")):
        return "tar.gz"
    if lower.endswith((".tar.bz2", ".tbz2", ".tbz")):
        return "tar.bz2"
    if lower.endswith((".tar.xz", ".txz")):
        return "tar.xz"
    if lower.endswith((".tar.zst", ".tar.zstd", ".tzst")):
        return "tar.zst"
    if lower.endswith(".gz"):
        return "gzip"
    if lower.endswith(".bz2"):
        return "bzip2"
    if lower.endswith(".xz"):
        return "xz"
    if lower.endswith((".zst", ".zstd")):
        return "zstd"
    if lower.endswith(".7z"):
        return "7z"
    if lower.endswith(".rar"):
        return "rar"
    return None


def material_dir_to_format(name: str) -> ArchiveFormat | None:
    value = MATERIAL_FORMAT_ALIASES.get(str(name or "").strip().lower())
    return value  # type: ignore[return-value]


def build_corpus_corruption_case(
    root: Path,
    *,
    source_path: Path,
    fmt: ArchiveFormat,
    seed: int,
    variant_index: int,
    damage_profile: str,
) -> CorruptionCase:
    clean = source_path.read_bytes()
    randomizer = random.Random(int(seed) + int(variant_index) * 1009)
    mutations, damage_flags = _corpus_profile_mutations(clean, fmt, randomizer, damage_profile)
    corrupted = apply_mutations(clean, mutations)
    oracle = _oracle_from_clean_bytes(clean, fmt)
    case_id = f"{source_path.stem}_{damage_profile}_{variant_index}"
    safe_case_id = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in case_id)
    return _write_corpus_case(
        root,
        safe_case_id,
        fmt,
        clean,
        corrupted,
        mutations,
        seed=seed,
        damage_flags=damage_flags,
        expected_statuses=("repaired", "partial", "unrepairable", "unsupported"),
        expected_files=oracle.get("files", {}),
        expected_payload=oracle.get("payload", b""),
        expected_bytes=clean if oracle.get("bytes_exact") else b"",
        output_required=False,
        builder_call="build_corpus_corruption_case(...)",
    )


def verify_repaired_output_against_oracle(case: CorruptionCase, path: Path) -> dict[str, Any]:
    try:
        return _verification_against_oracle(case, path)
    except Exception as exc:
        return {
            "status": "hard_negative",
            "label": -1,
            "complete": False,
            "partial": False,
            "completeness": 0.0,
            "matched_files": 0,
            "expected_files": len(case.expected_files),
            "error": str(exc),
        }


def apply_mutations(data: bytes, mutations: list[BinaryMutation]) -> bytes:
    output = bytearray(data)
    for mutation in mutations:
        operation = mutation.operation
        offset = max(0, min(len(output), int(operation.offset or 0)))
        size = max(0, int(operation.size or 0))
        patch_data = _operation_data(operation)
        if operation.op == "replace_range":
            output[offset:offset + size] = patch_data
        elif operation.op == "truncate":
            del output[offset:]
        elif operation.op == "append":
            output.extend(patch_data)
        elif operation.op == "insert":
            output[offset:offset] = patch_data
        elif operation.op == "delete":
            del output[offset:offset + size]
        else:
            raise ValueError(f"unsupported mutation operation: {operation.op}")
    return bytes(output)


def _corpus_profile_mutations(
    data: bytes,
    fmt: ArchiveFormat,
    randomizer: random.Random,
    damage_profile: str,
) -> tuple[list[BinaryMutation], list[str]]:
    if not data:
        raise ValueError("source archive is empty")
    profile = str(damage_profile or "multi").lower()
    base_fmt = _base_archive_format(fmt)
    if base_fmt == "zip":
        return _zip_corpus_mutations(data, randomizer, profile)
    if base_fmt == "tar":
        return _tar_corpus_mutations(data, randomizer, profile)
    if base_fmt in {"gzip", "bzip2", "xz", "zstd"}:
        return _stream_corpus_mutations(data, fmt, randomizer, profile)
    if base_fmt == "7z":
        return _seven_zip_corpus_mutations(data, randomizer, profile)
    if base_fmt == "rar":
        return _rar_corpus_mutations(data, randomizer, profile)
    return _raw_corpus_mutations(data, base_fmt, randomizer, profile)


def _zip_corpus_mutations(data: bytes, randomizer: random.Random, profile: str) -> tuple[list[BinaryMutation], list[str]]:
    mutations: list[BinaryMutation] = []
    layer = _damage_layer(profile)
    eocd = data.rfind(b"PK\x05\x06")
    if eocd >= 0 and eocd + 22 <= len(data):
        if layer in {"structural", "structural_directory", "hard_negative"}:
            mutations.extend([
                _replace_bytes("corpus_zip_bad_eocd_counts", eocd + 8, struct.pack("<HH", 1, 99), "zip.eocd.entry_counts", "directory entry counts conflict"),
                _replace_bytes("corpus_zip_bad_eocd_cd_offset", eocd + 16, struct.pack("<I", 0), "zip.eocd.cd_offset", "central directory offset points at start"),
            ])
        if layer == "partial_recoverable":
            mutations.append(_truncate("corpus_zip_drop_central_directory", eocd, "zip.central_directory", "central directory is missing but local headers remain"))
    else:
        mutations.append(_truncate("corpus_zip_drop_tail_directory", max(1, len(data) * 4 // 5), "zip.central_directory", "tail directory is truncated"))
    if layer == "hard_negative":
        payload_offset = _middle_offset(data, randomizer)
        mutations.append(_replace_byte("corpus_zip_flip_payload_byte", payload_offset, data[payload_offset] ^ 0x41, "zip.local_payload", "payload checksum may fail"))
    if ("missing_volume" in profile or layer == "partial_recoverable") and len(data) > 128:
        mutations.append(_delete("corpus_zip_delete_middle_volume_bytes", max(1, len(data) // 3), max(8, len(data) // 20), "zip.missing_volume", "middle archive bytes are missing"))
    if layer in {"structural", "hard_negative"}:
        mutations.append(_append("corpus_zip_append_tail_junk", _random_junk(randomizer, "ZIPTAIL", 12, 48), "archive.tail", "extra bytes after archive"))
    if "boundary" in profile or "sfx" in profile:
        mutations.append(_insert("corpus_zip_insert_sfx_prefix", 0, b"MZ-SUNPACK-CORPUS" + _random_junk(randomizer, "SFX", 8, 24), "zip.sfx.prefix", "archive is embedded behind a carrier prefix"))
    flags = ["central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"]
    if layer == "hard_negative":
        flags.extend(["checksum_error", "crc_error", "damaged"])
    if any(mutation.zone in {"archive.tail", "zip.sfx.prefix"} for mutation in mutations):
        flags.extend(["trailing_junk", "boundary_unreliable"])
    if layer == "partial_recoverable":
        flags.extend(["missing_volume", "input_truncated"])
    return mutations, _dedupe_list(flags)


def _tar_corpus_mutations(data: bytes, randomizer: random.Random, profile: str) -> tuple[list[BinaryMutation], list[str]]:
    mutations: list[BinaryMutation] = []
    layer = _damage_layer(profile)
    if len(data) >= 512:
        mutations.append(_replace_bytes("corpus_tar_zero_header_checksum", 148, b"000000\0 ", "tar.header.checksum", "header checksum must be recomputed"))
    if layer in {"partial_recoverable", "structural_directory"} and len(data) > 2048:
        mutations.append(_truncate("corpus_tar_drop_zero_blocks_or_member_tail", max(512, len(data) - 1024), "tar.trailing_zero_blocks", "tar end marker or final member is truncated"))
    elif layer in {"structural", "hard_negative"}:
        mutations.append(_append("corpus_tar_append_tail_junk", _random_junk(randomizer, "TARTAIL", 8, 32), "archive.tail", "extra bytes after tar stream"))
    if layer == "hard_negative":
        payload = _middle_offset(data, randomizer)
        mutations.append(_replace_byte("corpus_tar_flip_payload_byte", payload, data[payload] ^ 0x23, "tar.payload", "member payload may be damaged"))
    if "boundary" in profile:
        mutations.append(_append("corpus_tar_append_boundary_junk", _random_junk(randomizer, "TARBOUND", 8, 32), "archive.tail", "boundary has trailing junk"))
    flags = ["tar_checksum_bad"]
    if any(mutation.operation.op == "truncate" for mutation in mutations):
        flags.extend(["missing_end_block", "probably_truncated"])
    if any(mutation.zone == "archive.tail" for mutation in mutations):
        flags.extend(["trailing_junk", "boundary_unreliable"])
    if layer == "hard_negative":
        flags.extend(["checksum_error", "damaged"])
    return mutations, _dedupe_list(flags)


def _stream_corpus_mutations(data: bytes, fmt: ArchiveFormat, randomizer: random.Random, profile: str) -> tuple[list[BinaryMutation], list[str]]:
    mutations: list[BinaryMutation] = []
    layer = _damage_layer(profile)
    base_fmt = _base_archive_format(fmt)
    is_tar_wrapped = str(fmt).startswith("tar.")
    if layer == "partial_recoverable" and not is_tar_wrapped:
        layer = "structural"
    if base_fmt == "gzip" and len(data) > 16 and layer in {"structural", "structural_directory", "hard_negative"}:
        mutations.append(_replace_bytes("corpus_gzip_zero_footer", len(data) - 8, b"\0" * 8, "gzip.footer", "footer CRC/ISIZE is invalid"))
    if layer == "hard_negative":
        payload_offset = _middle_offset(data, randomizer)
        mutations.append(_replace_byte(f"corpus_{base_fmt}_flip_payload_byte", payload_offset, data[payload_offset] ^ 0x35, f"{base_fmt}.payload", "compressed payload may be damaged"))
    if len(data) > 64 and layer in {"partial_recoverable", "hard_negative"}:
        mutations.append(_truncate(f"corpus_{base_fmt}_truncate_stream_tail", max(1, len(data) * 9 // 10), f"{base_fmt}.stream_tail", "compressed stream tail is truncated"))
    if layer in {"structural", "hard_negative"}:
        mutations.append(_append(f"corpus_{base_fmt}_append_tail_junk", _random_junk(randomizer, f"{base_fmt.upper()}TAIL", 8, 32), "archive.tail", "extra bytes after compressed stream"))
    if "boundary" in profile:
        mutations.append(_insert(f"corpus_{base_fmt}_insert_carrier_prefix", 0, b"MZ-SUNPACK-STREAM" + _random_junk(randomizer, "SFX", 8, 24), f"{base_fmt}.sfx.prefix", "compressed stream is embedded behind a carrier prefix"))
    if not mutations:
        mutations.append(_append(f"corpus_{base_fmt}_append_tail_junk", _random_junk(randomizer, f"{base_fmt.upper()}TAIL", 8, 32), "archive.tail", "extra bytes after compressed stream"))
    flags: list[str] = []
    if any(mutation.operation.op == "truncate" for mutation in mutations):
        flags.extend(["input_truncated", "probably_truncated", "unexpected_end"])
    if layer == "hard_negative":
        flags.extend(["checksum_error", "crc_error", "damaged", "data_error"])
    elif base_fmt == "gzip" and any(mutation.zone == "gzip.footer" for mutation in mutations):
        flags.extend(["gzip_footer_bad", "checksum_error"])
    if any(mutation.zone == "archive.tail" or "sfx" in mutation.zone for mutation in mutations):
        flags.extend(["trailing_junk", "boundary_unreliable"])
    return mutations, _dedupe_list(flags or ["damaged"])


def _seven_zip_corpus_mutations(data: bytes, randomizer: random.Random, profile: str) -> tuple[list[BinaryMutation], list[str]]:
    mutations: list[BinaryMutation] = []
    layer = _damage_layer(profile)
    if len(data) > 32:
        mutations.append(_replace_bytes("corpus_7z_bad_start_crc", 8, b"\0\0\0\0", "7z.start_header_crc", "start header CRC is invalid"))
        if layer in {"structural_directory", "hard_negative"}:
            mutations.append(_replace_bytes("corpus_7z_bad_next_crc", 28, b"\0\0\0\0", "7z.next_header_crc", "next header CRC is invalid"))
    if layer == "hard_negative":
        payload_offset = _middle_offset(data, randomizer)
        mutations.append(_replace_byte("corpus_7z_flip_payload_byte", payload_offset, data[payload_offset] ^ 0x17, "7z.payload", "packed stream may be damaged"))
    if layer in {"structural", "hard_negative"}:
        mutations.append(_append("corpus_7z_append_tail_junk", _random_junk(randomizer, "7ZTAIL", 8, 32), "archive.tail", "extra bytes after 7z stream"))
    if layer == "partial_recoverable" and len(data) > 64:
        mutations.append(_truncate("corpus_7z_drop_stream_tail", max(1, len(data) - 32), "7z.stream_tail", "7z stream tail is truncated"))
    if "sfx" in profile or "boundary" in profile:
        mutations.append(_insert("corpus_7z_insert_sfx_prefix", 0, b"MZ-SUNPACK-7Z" + _random_junk(randomizer, "SFX", 8, 24), "7z.sfx.prefix", "7z payload is embedded behind a carrier prefix"))
    if not mutations:
        mutations.append(_append("corpus_7z_append_tail_junk", _random_junk(randomizer, "7ZTAIL", 8, 32), "archive.tail", "extra bytes after 7z stream"))
    flags = ["start_header_crc_bad"]
    if any(mutation.zone == "7z.next_header_crc" for mutation in mutations):
        flags.append("next_header_crc_bad")
    if layer == "hard_negative":
        flags.extend(["packed_stream_bad", "checksum_error", "damaged", "data_error"])
    if layer == "partial_recoverable":
        flags.extend(["input_truncated", "probably_truncated"])
    if any(mutation.zone in {"archive.tail", "7z.sfx.prefix"} for mutation in mutations):
        flags.extend(["trailing_junk", "boundary_unreliable"])
    return mutations, _dedupe_list(flags)


def _rar_corpus_mutations(data: bytes, randomizer: random.Random, profile: str) -> tuple[list[BinaryMutation], list[str]]:
    layer = _damage_layer(profile)
    mutations: list[BinaryMutation] = []
    if layer == "hard_negative":
        payload_offset = _middle_offset(data, randomizer)
        mutations.append(_replace_byte("corpus_rar_flip_file_block_byte", payload_offset, data[payload_offset] ^ 0x29, "rar.file_block", "file block may be damaged"))
    if layer in {"structural", "hard_negative"}:
        mutations.append(_append("corpus_rar_append_tail_junk", _random_junk(randomizer, "RARTAIL", 8, 32), "archive.tail", "extra bytes after rar stream"))
    if len(data) > 64 and layer in {"partial_recoverable", "hard_negative", "structural_directory"}:
        mutations.append(_truncate("corpus_rar_drop_end_block", max(1, len(data) - 32), "rar.end_block", "end block may be missing"))
    if "sfx" in profile or "boundary" in profile:
        mutations.append(_insert("corpus_rar_insert_sfx_prefix", 0, b"MZ-SUNPACK-RAR" + _random_junk(randomizer, "SFX", 8, 24), "rar.sfx.prefix", "rar payload is embedded behind a carrier prefix"))
    if not mutations:
        mutations.append(_append("corpus_rar_append_tail_junk", _random_junk(randomizer, "RARTAIL", 8, 32), "archive.tail", "extra bytes after rar stream"))
    flags: list[str] = []
    if layer == "hard_negative":
        flags.extend(["file_block_bad", "checksum_error", "damaged", "data_error"])
    if any(mutation.operation.op == "truncate" for mutation in mutations):
        flags.append("missing_end_block")
    if any(mutation.zone in {"archive.tail", "rar.sfx.prefix"} for mutation in mutations):
        flags.extend(["trailing_junk", "boundary_unreliable"])
    return mutations, _dedupe_list(flags)


def _raw_corpus_mutations(data: bytes, fmt: ArchiveFormat, randomizer: random.Random, profile: str) -> tuple[list[BinaryMutation], list[str]]:
    layer = _damage_layer(profile)
    header_offset = min(len(data) - 1, max(0, len(data) // 16))
    mutations = [
        _replace_byte(f"corpus_{fmt}_flip_header_byte", header_offset, data[header_offset] ^ 0x11, f"{fmt}.header", "header byte changed"),
    ]
    if layer == "hard_negative":
        payload_offset = _middle_offset(data, randomizer)
        mutations.append(_replace_byte(f"corpus_{fmt}_flip_payload_byte", payload_offset, data[payload_offset] ^ 0x22, f"{fmt}.payload", "payload byte changed"))
    if layer in {"structural", "hard_negative"}:
        mutations.append(_append(f"corpus_{fmt}_append_tail_junk", _random_junk(randomizer, "TAIL", 8, 32), "archive.tail", "extra bytes after archive"))
    return mutations, ["damaged", "checksum_error", "boundary_unreliable"]


def _damage_layer(profile: str) -> str:
    text = str(profile or "").lower()
    for layer in ("structural_directory", "partial_recoverable", "hard_negative", "structural"):
        if layer in text:
            return layer
    if "payload" in text or "block" in text:
        return "hard_negative"
    if "partial" in text or "truncate" in text or "missing" in text:
        return "partial_recoverable"
    if "directory" in text or "metadata" in text or "index" in text:
        return "structural_directory"
    return "structural"


def _dedupe_list(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        if value not in output:
            output.append(value)
    return output


def _oracle_from_clean_bytes(data: bytes, fmt: ArchiveFormat) -> dict[str, Any]:
    base_fmt = _base_archive_format(fmt)
    if base_fmt == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                return {"files": {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}}
        except Exception:
            return {"bytes_exact": True}
    if base_fmt == "tar":
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                files = {}
                for item in archive.getmembers():
                    if not item.isfile():
                        continue
                    member = archive.extractfile(item)
                    if member is not None:
                        files[item.name] = member.read()
                return {"files": files}
        except Exception:
            return {"bytes_exact": True}
    if base_fmt == "gzip":
        try:
            return {"payload": gzip.decompress(data)}
        except Exception:
            return {"bytes_exact": True}
    if base_fmt == "bzip2":
        try:
            return {"payload": bz2.decompress(data)}
        except Exception:
            return {"bytes_exact": True}
    if base_fmt == "xz":
        try:
            return {"payload": lzma.decompress(data)}
        except Exception:
            return {"bytes_exact": True}
    return {"bytes_exact": True}


def _write_corpus_case(
    root: Path,
    case_id: str,
    fmt: ArchiveFormat,
    clean: bytes,
    corrupted: bytes,
    mutations: list[BinaryMutation],
    *,
    seed: int,
    damage_flags: list[str],
    expected_statuses: tuple[str, ...],
    expected_files: dict[str, bytes] | None = None,
    expected_payload: bytes = b"",
    expected_bytes: bytes = b"",
    output_required: bool = False,
    builder_call: str = "",
) -> CorruptionCase:
    root.mkdir(parents=True, exist_ok=True)
    ext = _extension_for_format(fmt)
    clean_path = root / f"clean-{case_id}.{ext}"
    damaged_path = root / f"{case_id}.{ext}"
    clean_path.write_bytes(clean)
    damaged_path.write_bytes(corrupted)
    return CorruptionCase(
        case_id=case_id,
        format=fmt,
        seed=int(seed),
        source_input={"kind": "file", "path": str(damaged_path), "format_hint": fmt},
        clean_source_input={"kind": "file", "path": str(clean_path), "format_hint": fmt},
        clean_data=clean,
        corrupted_data=corrupted,
        mutations=list(mutations),
        damage_flags=list(damage_flags),
        expected_statuses=expected_statuses,
        expected_files=dict(expected_files or {}),
        expected_payload=expected_payload,
        expected_bytes=expected_bytes,
        output_required=output_required,
        builder_call=builder_call,
    )


def _verification_against_oracle(case: CorruptionCase, path: Path) -> dict[str, Any]:
    if case.expected_bytes:
        matched = path.read_bytes() == case.expected_bytes
        return _oracle_status(complete=matched, partial=False, hard_negative=not matched, completeness=1.0 if matched else 0.0)
    if case.expected_payload:
        payload = _decompress_payload(path, case.format)
        matched = payload == case.expected_payload
        prefix = case.expected_payload.startswith(payload) and bool(payload)
        return _oracle_status(complete=matched, partial=prefix and not matched, hard_negative=not (matched or prefix), completeness=(len(payload) / max(1, len(case.expected_payload))) if prefix or matched else 0.0)
    if case.expected_files:
        recovered = _read_archive_files(path, case.format)
        matched = {
            name: payload
            for name, payload in recovered.items()
            if case.expected_files.get(name) == payload
        }
        wrong_overlap = any(name in case.expected_files and case.expected_files[name] != payload for name, payload in recovered.items())
        completeness = len(matched) / max(1, len(case.expected_files))
        return {
            **_oracle_status(complete=completeness >= 0.999, partial=0.0 < completeness < 0.999, hard_negative=wrong_overlap and completeness <= 0.0, completeness=completeness),
            "matched_files": len(matched),
            "expected_files": len(case.expected_files),
            "recovered_files": len(recovered),
        }
    return _oracle_status(complete=False, partial=False, hard_negative=False, completeness=0.0)


def _read_archive_files(path: Path, fmt: ArchiveFormat) -> dict[str, bytes]:
    base_fmt = _base_archive_format(fmt)
    if base_fmt == "zip":
        with zipfile.ZipFile(path) as archive:
            return {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
    if base_fmt == "tar":
        with tarfile.open(path) as archive:
            output = {}
            for item in archive.getmembers():
                if not item.isfile():
                    continue
                member = archive.extractfile(item)
                if member is not None:
                    output[item.name] = member.read()
            return output
    return {}


def _decompress_payload(path: Path, fmt: ArchiveFormat) -> bytes:
    raw = path.read_bytes()
    base_fmt = _base_archive_format(fmt)
    if base_fmt == "gzip":
        return gzip.decompress(raw)
    if base_fmt == "bzip2":
        return bz2.decompress(raw)
    if base_fmt == "xz":
        return lzma.decompress(raw)
    return raw


def _oracle_status(*, complete: bool, partial: bool, hard_negative: bool, completeness: float) -> dict[str, Any]:
    if hard_negative:
        label = -1
        status = "hard_negative"
    elif complete:
        label = 3
        status = "complete"
    elif partial:
        label = 1
        status = "partial"
    else:
        label = 0
        status = "no_progress"
    return {
        "status": status,
        "label": label,
        "complete": bool(complete),
        "partial": bool(partial),
        "completeness": max(0.0, min(1.0, float(completeness or 0.0))),
    }


def _middle_offset(data: bytes, randomizer: random.Random) -> int:
    if len(data) <= 1:
        return 0
    start = max(0, len(data) // 4)
    end = max(start + 1, len(data) * 3 // 4)
    return randomizer.randrange(start, min(len(data), end))


def _random_junk(randomizer: random.Random, prefix: str, min_len: int, max_len: int) -> bytes:
    return prefix.encode("ascii") + randomizer.randbytes(randomizer.randrange(min_len, max_len + 1))


def _mutation_kind(name: str, op: str) -> str:
    lowered = str(name or "").lower()
    for marker in ("eocd", "central_directory", "payload", "footer", "header", "tail", "sfx", "volume", "crc", "checksum", "truncate"):
        if marker in lowered:
            return marker
    return str(op or "mutation")


def repair_result_summary(result: Any) -> dict:
    repaired_input = getattr(result, "repaired_input", None)
    diagnosis = getattr(result, "diagnosis", None)
    return {
        "status": str(getattr(result, "status", "")),
        "ok": bool(getattr(result, "ok", False)),
        "module_name": str(getattr(result, "module_name", "")),
        "format": str(getattr(result, "format", "")),
        "confidence": float(getattr(result, "confidence", 0.0) or 0.0),
        "partial": bool(getattr(result, "partial", False)),
        "message": str(getattr(result, "message", "")),
        "actions": list(getattr(result, "actions", []) or []),
        "warnings": list(getattr(result, "warnings", []) or []),
        "damage_flags": list(getattr(result, "damage_flags", []) or []),
        "repaired_input": _source_input_summary(repaired_input if isinstance(repaired_input, dict) else {}),
        "diagnosis": _diagnosis_summary(diagnosis if isinstance(diagnosis, dict) else {}),
    }


def verify_corruption_case_output(case: CorruptionCase, path: Path) -> None:
    if case.expected_bytes:
        assert path.read_bytes() == case.expected_bytes
        return
    if case.format == "zip":
        with zipfile.ZipFile(path) as archive:
            assert sorted(archive.namelist()) == sorted(case.expected_files)
            for name, payload in case.expected_files.items():
                assert archive.read(name) == payload
        return
    if case.format == "tar":
        with tarfile.open(path) as archive:
            names = sorted(item.name for item in archive.getmembers() if item.isfile())
            assert names == sorted(case.expected_files)
            for name, payload in case.expected_files.items():
                member = archive.extractfile(name)
                assert member is not None
                assert member.read() == payload
        return
    if case.format == "gzip":
        assert gzip.decompress(path.read_bytes()) == case.expected_payload
        return
    if case.format == "bzip2":
        assert bz2.decompress(path.read_bytes()) == case.expected_payload
        return
    if case.format == "xz":
        assert lzma.decompress(path.read_bytes()) == case.expected_payload
        return
    raise AssertionError(f"unsupported verification format: {case.format}")


def _source_input_summary(source_input: dict) -> dict:
    kind = str(source_input.get("kind") or source_input.get("open_mode") or "")
    summary = {
        "kind": kind,
        "format_hint": str(source_input.get("format_hint") or source_input.get("format") or ""),
    }
    path = str(source_input.get("path") or source_input.get("entry_path") or "")
    if path:
        summary["path_name"] = Path(path).name
    ranges = source_input.get("ranges")
    if isinstance(ranges, list):
        summary["range_count"] = len(ranges)
        summary["range_path_names"] = [
            Path(str(item.get("path") or "")).name
            for item in ranges
            if isinstance(item, dict) and item.get("path")
        ]
    parts = source_input.get("parts")
    if isinstance(parts, list):
        summary["part_count"] = len(parts)
        summary["part_path_names"] = [
            Path(str(item.get("path") or "")).name
            for item in parts
            if isinstance(item, dict) and item.get("path")
        ]
    return {
        key: value
        for key, value in summary.items()
        if value != "" and value != [] and value != 0
    }


def _diagnosis_summary(diagnosis: dict) -> dict:
    capability = diagnosis.get("repair_capability") if isinstance(diagnosis.get("repair_capability"), dict) else {}
    coverage = diagnosis.get("archive_coverage") if isinstance(diagnosis.get("archive_coverage"), dict) else {}
    return {
        "status": diagnosis.get("status"),
        "format": diagnosis.get("format"),
        "confidence": diagnosis.get("confidence"),
        "repairable": diagnosis.get("repairable"),
        "categories": list(diagnosis.get("categories") or []),
        "damage_flags": list(diagnosis.get("damage_flags") or []),
        "notes": list(diagnosis.get("notes") or []),
        "archive_coverage": {
            key: coverage.get(key)
            for key in ("completeness", "recoverable_upper_bound", "complete_files", "partial_files", "failed_files", "missing_files")
            if key in coverage
        },
        "repair_capability": {
            key: capability.get(key)
            for key in ("automatic_unrepairable", "reason", "reasons", "message")
            if key in capability
        },
        "diagnosis_keys": sorted(str(key) for key in diagnosis),
    }


def _replace_byte(name: str, offset: int, value: int, zone: str, expected_effect: str) -> BinaryMutation:
    return _replace_bytes(name, offset, bytes([value & 0xFF]), zone, expected_effect)


def _replace_bytes(name: str, offset: int, payload: bytes, zone: str, expected_effect: str) -> BinaryMutation:
    return BinaryMutation(
        name=name,
        operation=PatchOperation.replace_bytes(
            offset=offset,
            data=payload,
            details={"mutation": name, "zone": zone},
        ),
        zone=zone,
        expected_effect=expected_effect,
    )


def _append(name: str, payload: bytes, zone: str, expected_effect: str) -> BinaryMutation:
    return BinaryMutation(
        name=name,
        operation=PatchOperation.append_bytes(
            payload,
            details={"mutation": name, "zone": zone},
        ),
        zone=zone,
        expected_effect=expected_effect,
    )


def _insert(name: str, offset: int, payload: bytes, zone: str, expected_effect: str) -> BinaryMutation:
    return BinaryMutation(
        name=name,
        operation=PatchOperation(
            op="insert",
            offset=offset,
            size=len(payload),
            data_b64=base64.b64encode(payload).decode("ascii"),
            details={"mutation": name, "zone": zone},
        ),
        zone=zone,
        expected_effect=expected_effect,
    )


def _delete(name: str, offset: int, size: int, zone: str, expected_effect: str) -> BinaryMutation:
    return BinaryMutation(
        name=name,
        operation=PatchOperation.delete_range(
            offset=offset,
            size=size,
            details={"mutation": name, "zone": zone},
        ),
        zone=zone,
        expected_effect=expected_effect,
    )


def _truncate(name: str, offset: int, zone: str, expected_effect: str) -> BinaryMutation:
    return BinaryMutation(
        name=name,
        operation=PatchOperation(
            op="truncate",
            offset=offset,
            details={"mutation": name, "zone": zone},
        ),
        zone=zone,
        expected_effect=expected_effect,
    )


def _operation_data(operation: PatchOperation) -> bytes:
    if not operation.data_b64:
        return b""
    return base64.b64decode(operation.data_b64.encode("ascii"))


def _tag_combined_mutation(mutation: BinaryMutation, group_index: int, mutation_index: int) -> BinaryMutation:
    details = dict(mutation.operation.details)
    details["combination_group"] = group_index
    details["combination_index"] = mutation_index
    operation = PatchOperation(
        op=mutation.operation.op,
        target=mutation.operation.target,
        offset=mutation.operation.offset,
        size=mutation.operation.size,
        part_index=mutation.operation.part_index,
        data_b64=mutation.operation.data_b64,
        data_ref=mutation.operation.data_ref,
        details=details,
    )
    return BinaryMutation(
        name=mutation.name,
        operation=operation,
        zone=mutation.zone,
        expected_effect=mutation.expected_effect,
    )


def _pseudo_random_payload(seed: int, size: int) -> bytes:
    generator = random.Random(seed)
    return generator.randbytes(size)


def zlib_crc32(data: bytes | bytearray) -> int:
    return zlib.crc32(bytes(data)) & 0xFFFFFFFF


def _seven_zip_bytes(*, minor: int = 4, gap: bytes = b"abcde", next_header: bytes = b"\x01") -> bytes:
    start_header = struct.pack("<QQI", len(gap), len(next_header), zlib_crc32(next_header))
    return (
        b"7z\xbc\xaf\x27\x1c"
        + bytes([0, minor])
        + struct.pack("<I", zlib_crc32(start_header))
        + start_header
        + gap
        + next_header
    )


RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"


def _rar5_vint(value: int) -> bytes:
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            output.append(byte | 0x80)
        else:
            output.append(byte)
            return bytes(output)


def _rar5_block(header_type: int, flags: int = 0, data: bytes = b"") -> bytes:
    fields = _rar5_vint(header_type) + _rar5_vint(flags)
    if data:
        flags |= 0x0002
        fields = _rar5_vint(header_type) + _rar5_vint(flags) + _rar5_vint(len(data))
    header_size = _rar5_vint(len(fields))
    header_data = header_size + fields
    return zlib_crc32(header_data).to_bytes(4, "little") + header_data + data


def _rar5_bytes(*, file_payload: bytes = b"") -> bytes:
    file_block = _rar5_block(2, data=file_payload) if file_payload else b""
    return RAR5_MAGIC + _rar5_block(1) + file_block + _rar5_block(5)


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def _zip_eocd_offset(data: bytes) -> int:
    offset = data.rfind(b"PK\x05\x06")
    if offset < 0:
        raise ValueError("ZIP EOCD was not found")
    return offset


def _zip_cd_offset(data: bytes) -> int:
    return struct.unpack_from("<I", data, _zip_eocd_offset(data) + 16)[0]


def _zip_payload_offset(data: bytes, name: str) -> int:
    encoded = name.encode("utf-8")
    offset = data.find(b"PK\x03\x04")
    while offset >= 0:
        name_len, extra_len = struct.unpack_from("<HH", data, offset + 26)
        name_start = offset + 30
        if data[name_start:name_start + name_len] == encoded:
            return name_start + name_len + extra_len
        offset = data.find(b"PK\x03\x04", offset + 4)
    raise ValueError(f"ZIP entry was not found: {name}")


def _tar_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _tar_payload_end(data: bytes, entries: dict[str, bytes]) -> int:
    offset = 0
    for payload in entries.values():
        offset += 512 + ((len(payload) + 511) // 512) * 512
    if offset > len(data):
        raise ValueError("computed TAR payload end exceeds archive size")
    return offset


def _write_split_ranges(root: Path, stem: str, data: bytes, split_points: list[int]) -> list[dict]:
    points = [0]
    points.extend(sorted({max(0, min(len(data), int(point))) for point in split_points if 0 < int(point) < len(data)}))
    points.append(len(data))
    ranges: list[dict] = []
    for index, (start, end) in enumerate(zip(points, points[1:]), start=1):
        path = root / f"{stem}.{index:03d}"
        chunk = data[start:end]
        path.write_bytes(chunk)
        ranges.append({"path": str(path), "start": 0, "end": len(chunk)})
    return ranges


def _clean_archive_bytes(fmt: ArchiveFormat, seed: int) -> bytes:
    payload = b"raw corruption payload" + _pseudo_random_payload(seed + 100, 64)
    if fmt == "zip":
        return _zip_bytes({"payload.bin": payload})
    if fmt == "tar":
        return _tar_bytes({"payload.bin": payload})
    if fmt == "gzip":
        return gzip.compress(payload)
    if fmt == "bzip2":
        return bz2.compress(payload)
    if fmt == "xz":
        return lzma.compress(payload, format=lzma.FORMAT_XZ)
    if fmt == "7z":
        return _seven_zip_bytes(next_header=b"\x01\x02")
    if fmt == "rar":
        return _rar5_bytes(file_payload=payload[:16])
    raise ValueError(f"unsupported format: {fmt}")


def _extension_for_format(fmt: ArchiveFormat) -> str:
    return {
        "zip": "zip",
        "tar": "tar",
        "gzip": "gz",
        "bzip2": "bz2",
        "xz": "xz",
        "zstd": "zst",
        "7z": "7z",
        "rar": "rar",
        "tar.gz": "tar.gz",
        "tar.bz2": "tar.bz2",
        "tar.xz": "tar.xz",
        "tar.zst": "tar.zst",
    }[fmt]


def _base_archive_format(fmt: str) -> ArchiveFormat:
    normalized = MATERIAL_FORMAT_ALIASES.get(str(fmt or "").strip().lower(), str(fmt or "").strip().lower())
    if normalized == "tar.gz":
        return "gzip"
    if normalized == "tar.bz2":
        return "bzip2"
    if normalized == "tar.xz":
        return "xz"
    if normalized == "tar.zst":
        return "zstd"
    return normalized  # type: ignore[return-value]


def _semantic_zones(data: bytes, fmt: ArchiveFormat) -> dict[str, tuple[int, int]]:
    size = len(data)
    if size <= 0:
        return {name: (0, 0) for name in ("header", "payload", "footer", "boundary")}
    header_end = min(size, max(1, min(64, size // 5 or 1)))
    footer_start = min(size, max(header_end, size - max(1, min(64, size // 5 or 1))))
    payload_start = min(size, header_end)
    payload_end = max(payload_start, footer_start)
    boundary = _format_boundary(data, fmt, header_end, footer_start)
    return {
        "header": (0, header_end),
        "payload": (payload_start, payload_end),
        "footer": (footer_start, size),
        "boundary": boundary,
    }


def _format_boundary(data: bytes, fmt: ArchiveFormat, header_end: int, footer_start: int) -> tuple[int, int]:
    if fmt == "zip":
        eocd = data.rfind(b"PK\x05\x06")
        if eocd >= 0:
            return eocd, min(len(data), eocd + 22)
    if fmt == "7z":
        return 8, min(len(data), 32)
    if fmt == "rar":
        return 0, min(len(data), len(RAR5_MAGIC) + 8)
    return max(0, footer_start - 4), min(len(data), footer_start + 4)


def _fake_magic_for_format(fmt: ArchiveFormat) -> bytes:
    return {
        "zip": b"PK\x03\x04",
        "7z": b"7z\xbc\xaf\x27\x1c",
        "rar": RAR5_MAGIC,
        "gzip": b"\x1f\x8b\x08",
        "bzip2": b"BZh",
        "xz": b"\xfd7zXZ\x00",
        "tar": b"ustar",
    }.get(fmt, b"")


def _build_encrypted_zip(root: Path, *, password: str) -> bytes:
    tool = Path(__file__).resolve().parents[2] / "tools" / "7z.exe"
    if not tool.is_file():
        raise FileNotFoundError(str(tool))
    root.mkdir(parents=True, exist_ok=True)
    payload = root / "encrypted-payload.txt"
    archive = root / "encrypted-source.zip"
    payload.write_bytes(b"encrypted zip payload")
    if archive.exists():
        archive.unlink()
    command = [
        str(tool),
        "a",
        "-tzip",
        f"-p{password}",
        "-mem=ZipCrypto",
        str(archive),
        str(payload),
    ]
    completed = subprocess.run(command, cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if completed.returncode != 0 or not archive.is_file():
        raise RuntimeError(f"7z encrypted ZIP fixture failed: {completed.stderr or completed.stdout}")
    return archive.read_bytes()
