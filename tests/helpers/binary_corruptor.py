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

from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor
from smart_unpacker.contracts.archive_state import PatchOperation, PatchPlan


ArchiveFormat = Literal["zip", "tar", "gzip", "bzip2", "xz", "7z", "rar"]


@dataclass(frozen=True)
class BinaryMutation:
    name: str
    operation: PatchOperation
    zone: str = ""
    expected_effect: str = ""

    def to_dict(self) -> dict:
        payload = {
            "name": self.name,
            "operation": self.operation.to_dict(),
        }
        if self.zone:
            payload["zone"] = self.zone
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

    def regression_snippet(self, root_expr: str = "tmp_path / \"case\"") -> str:
        builder = self.builder_call or f"{self.case_id}(root)"
        return "\n".join([
            "from tests.helpers.binary_corruptor import BinaryCorruptor, apply_mutations",
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
        from smart_unpacker.contracts.archive_state import ArchiveState

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
            expected_statuses=("partial",),
            expected_module="zip_central_directory_rebuild",
            expected_files={
                "good.txt": entries["good.txt"],
                "keep.bin": entries["keep.bin"],
            },
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
        "7z": "7z",
        "rar": "rar",
    }[fmt]


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
