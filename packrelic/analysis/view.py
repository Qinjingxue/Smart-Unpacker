import os
import math
from binascii import crc32
from dataclasses import dataclass
from collections import Counter

from packrelic_native import AnalysisBinaryView as _NativeAnalysisBinaryView
from packrelic_native import AnalysisMultiVolumeView as _NativeAnalysisMultiVolumeView
from packrelic.contracts.archive_state import ArchiveState
from packrelic.support.archive_state_view import ArchiveStateByteView


@dataclass(frozen=True)
class ReadStats:
    read_bytes: int
    cache_hits: int


class SharedBinaryView:
    """Thread-safe random-access binary view with a small shared LRU cache."""

    def __init__(
        self,
        path: str,
        *,
        cache_bytes: int = 64 * 1024 * 1024,
        max_read_bytes: int | None = None,
        max_concurrent_reads: int = 1,
    ):
        self.path = path
        self.size = os.path.getsize(path)
        self.cache_bytes = max(0, int(cache_bytes or 0))
        self.max_read_bytes = max_read_bytes if max_read_bytes is None else max(0, int(max_read_bytes))
        self._native = _NativeAnalysisBinaryView(
            path,
            cache_bytes=self.cache_bytes,
            max_read_bytes=self.max_read_bytes,
            max_concurrent_reads=max_concurrent_reads,
        )
        self.size = int(self._native.size)

    def read_at(self, offset: int, size: int) -> bytes:
        return bytes(self._native.read_at(int(offset), int(size)))

    def read_tail(self, size: int) -> bytes:
        return bytes(self._native.read_tail(int(size)))

    def stats(self) -> ReadStats:
        stats = self._native.stats()
        return ReadStats(
            read_bytes=int(stats.get("read_bytes", 0) or 0),
            cache_hits=int(stats.get("cache_hits", 0) or 0),
        )

    def signature_prepass(self, *, head_bytes: int, tail_bytes: int) -> dict | None:
        return dict(self._native.signature_prepass(int(head_bytes), int(tail_bytes)))

    def probe_zip(self, *, eocd_offset: int, max_cd_entries_to_walk: int = 64) -> dict | None:
        return dict(self._native.probe_zip(int(eocd_offset), int(max_cd_entries_to_walk)))

    def probe_rar(self, *, start_offset: int, max_blocks_to_walk: int = 4096) -> dict | None:
        return dict(self._native.probe_rar(int(start_offset), int(max_blocks_to_walk)))

    def probe_seven_zip(self, *, start_offset: int, max_next_header_check_bytes: int = 1024 * 1024) -> dict | None:
        return dict(self._native.probe_seven_zip(int(start_offset), int(max_next_header_check_bytes)))

    def probe_tar(self, *, start_offset: int = 0, max_entries_to_walk: int = 64) -> dict | None:
        return dict(self._native.probe_tar(int(start_offset), int(max_entries_to_walk)))

    def probe_compression_stream(self, *, format: str) -> dict | None:
        return dict(self._native.probe_compression_stream(str(format)))

    def probe_compressed_tar(self, *, format: str, max_probe_bytes: int = 4 * 1024 * 1024) -> dict | None:
        return dict(self._native.probe_compressed_tar(str(format), int(max_probe_bytes)))

    def fuzzy_binary_profile(
        self,
        *,
        window_bytes: int = 64 * 1024,
        max_windows: int = 8,
        max_sample_bytes: int = 1024 * 1024,
        entropy_high_threshold: float = 6.8,
        entropy_low_threshold: float = 3.5,
        entropy_jump_threshold: float = 1.25,
        ngram_top_k: int = 8,
        max_ngram_sample_bytes: int = 256 * 1024,
    ) -> dict:
        return dict(self._native.fuzzy_binary_profile(
            int(window_bytes),
            int(max_windows),
            int(max_sample_bytes),
            float(entropy_high_threshold),
            float(entropy_low_threshold),
            float(entropy_jump_threshold),
            int(ngram_top_k),
            int(max_ngram_sample_bytes),
        ))

    def _reserve_read_budget(self, size: int) -> None:
        if self.max_read_bytes is None:
            return
        if self._read_bytes + size > self.max_read_bytes:
            raise RuntimeError("archive analysis read budget exceeded")

    def _store_cache_entry(self, key: tuple[int, int], data: bytes) -> None:
        if self.cache_bytes <= 0 or len(data) > self.cache_bytes:
            return
        self._cache[key] = data
        self._cache.move_to_end(key)
        self._cache_size += len(data)
        while self._cache_size > self.cache_bytes and self._cache:
            _, old = self._cache.popitem(last=False)
            self._cache_size -= len(old)


class MultiVolumeBinaryView:
    """Random-access logical view over ordered split-volume files."""

    def __init__(
        self,
        paths,
        *,
        cache_bytes: int = 64 * 1024 * 1024,
        max_read_bytes: int | None = None,
        max_concurrent_reads: int = 1,
    ):
        self.volumes = _normalize_volume_paths(paths)
        if not self.volumes:
            raise ValueError("MultiVolumeBinaryView requires at least one volume")
        self.path = self.volumes[0]
        self.cache_bytes = max(0, int(cache_bytes or 0))
        self.max_read_bytes = max_read_bytes if max_read_bytes is None else max(0, int(max_read_bytes))
        self._native = _NativeAnalysisMultiVolumeView(
            self.volumes,
            cache_bytes=self.cache_bytes,
            max_read_bytes=self.max_read_bytes,
            max_concurrent_reads=max_concurrent_reads,
        )
        self.path = str(self._native.path)
        self.size = int(self._native.size)

    def read_at(self, offset: int, size: int) -> bytes:
        return bytes(self._native.read_at(int(offset), int(size)))

    def read_tail(self, size: int) -> bytes:
        return bytes(self._native.read_tail(int(size)))

    def stats(self) -> ReadStats:
        stats = self._native.stats()
        return ReadStats(
            read_bytes=int(stats.get("read_bytes", 0) or 0),
            cache_hits=int(stats.get("cache_hits", 0) or 0),
        )

    def signature_prepass(self, *, head_bytes: int, tail_bytes: int) -> dict | None:
        return dict(self._native.signature_prepass(int(head_bytes), int(tail_bytes)))

    def probe_zip(self, *, eocd_offset: int, max_cd_entries_to_walk: int = 64) -> dict | None:
        return _probe_zip_view(self, int(eocd_offset), int(max_cd_entries_to_walk))

    def probe_rar(self, *, start_offset: int, max_blocks_to_walk: int = 4096) -> dict | None:
        return _probe_rar_view(self, int(start_offset), int(max_blocks_to_walk))

    def probe_seven_zip(self, *, start_offset: int, max_next_header_check_bytes: int = 1024 * 1024) -> dict | None:
        return _probe_seven_zip_view(self, int(start_offset), int(max_next_header_check_bytes))

    def fuzzy_binary_profile(
        self,
        *,
        window_bytes: int = 64 * 1024,
        max_windows: int = 8,
        max_sample_bytes: int = 1024 * 1024,
        entropy_high_threshold: float = 6.8,
        entropy_low_threshold: float = 3.5,
        entropy_jump_threshold: float = 1.25,
        ngram_top_k: int = 8,
        max_ngram_sample_bytes: int = 256 * 1024,
    ) -> dict:
        return dict(self._native.fuzzy_binary_profile(
            int(window_bytes),
            int(max_windows),
            int(max_sample_bytes),
            float(entropy_high_threshold),
            float(entropy_low_threshold),
            float(entropy_jump_threshold),
            int(ngram_top_k),
            int(max_ngram_sample_bytes),
        ))


class PatchedBinaryView:
    """Random-access analysis view over ArchiveState patch stacks."""

    def __init__(self, state: ArchiveState):
        self.state = state
        self.path = state.source.entry_path
        self._view = ArchiveStateByteView(state)
        self.size = int(self._view.size)

    def read_at(self, offset: int, size: int) -> bytes:
        return self._view.read_at(offset, size)

    def read_tail(self, size: int) -> bytes:
        return self._view.read_tail(size)

    def stats(self) -> ReadStats:
        stats = self._view.stats()
        return ReadStats(read_bytes=int(stats.read_bytes), cache_hits=int(stats.cache_hits))

    def signature_prepass(self, *, head_bytes: int, tail_bytes: int) -> dict | None:
        head_len = min(max(0, int(head_bytes)), self.size)
        tail_len = min(max(0, int(tail_bytes)), self.size)
        head = self.read_at(0, head_len)
        tail_offset = max(0, self.size - tail_len)
        tail = self.read_at(tail_offset, tail_len)
        hits = []
        for name, signature in _KNOWN_SIGNATURES.items():
            for offset in _find_all(head, signature):
                hits.append({"name": name, "offset": int(offset), "source": "head"})
            tail_start = 257 if name == "tar_ustar" else 0
            for offset in _find_all(tail[tail_start:], signature):
                absolute = tail_offset + tail_start + offset
                if absolute < head_len and any(hit["name"] == name and hit["offset"] == absolute for hit in hits):
                    continue
                hits.append({"name": name, "offset": int(absolute), "source": "tail"})
        hits.sort(key=lambda item: (int(item["offset"]), str(item["name"])))
        formats = sorted(_formats_from_hits(hits))
        return {
            "size": self.size,
            "head_bytes": len(head),
            "tail_bytes": len(tail),
            "hits": hits,
            "formats": formats,
            "patched": True,
            "patch_digest": self.state.effective_patch_digest(),
        }

    def probe_zip(self, *, eocd_offset: int, max_cd_entries_to_walk: int = 64) -> dict | None:
        return _probe_zip_view(self, int(eocd_offset), int(max_cd_entries_to_walk))

    def probe_rar(self, *, start_offset: int, max_blocks_to_walk: int = 4096) -> dict | None:
        return _probe_rar_view(self, int(start_offset), int(max_blocks_to_walk))

    def probe_seven_zip(self, *, start_offset: int, max_next_header_check_bytes: int = 1024 * 1024) -> dict | None:
        return _probe_seven_zip_view(self, int(start_offset), int(max_next_header_check_bytes))

    def probe_tar(self, *, start_offset: int = 0, max_entries_to_walk: int = 64) -> dict | None:
        return _probe_tar_view(self, int(start_offset), int(max_entries_to_walk))

    def probe_compression_stream(self, *, format: str) -> dict | None:
        return _probe_compression_stream_view(self, str(format))

    def probe_compressed_tar(self, *, format: str, max_probe_bytes: int = 4 * 1024 * 1024) -> dict | None:
        result = _probe_compression_stream_view(self, str(format))
        result["tar_plausible"] = False
        return result

    def fuzzy_binary_profile(
        self,
        *,
        window_bytes: int = 64 * 1024,
        max_windows: int = 8,
        max_sample_bytes: int = 1024 * 1024,
        entropy_high_threshold: float = 6.8,
        entropy_low_threshold: float = 3.5,
        entropy_jump_threshold: float = 1.25,
        ngram_top_k: int = 8,
        max_ngram_sample_bytes: int = 256 * 1024,
    ) -> dict:
        sample_size = min(self.size, max(1024, int(max_sample_bytes)))
        sample = self.read_at(0, sample_size)
        tail = self.read_tail(min(sample_size, max(1024, int(window_bytes))))
        entropy = _entropy(sample)
        return {
            "entropy_profile": {
                "avg_entropy": entropy,
                "head_entropy": _entropy(sample[:min(len(sample), int(window_bytes))]),
                "tail_entropy": _entropy(tail),
                "overall_high_entropy": entropy >= float(entropy_high_threshold),
                "head_low_entropy": _entropy(sample[:min(len(sample), int(window_bytes))]) <= float(entropy_low_threshold),
                "tail_low_entropy": _entropy(tail) <= float(entropy_low_threshold),
            },
            "byte_class_profile": {
                "head": _byte_class(sample[:min(len(sample), int(window_bytes))]),
                "tail": _byte_class(tail),
                "average": _byte_class(sample),
            },
            "window_anomalies": [],
            "run_profile": _run_profile(tail, self.size - len(tail)),
            "ngram_sketch": {"byte_histogram_top": _byte_histogram(sample, int(ngram_top_k)), "magic_like_hits": []},
            "hints": [],
            "patched": True,
        }


def _normalize_volume_paths(paths) -> list[str]:
    entries = list(paths or [])
    if entries and all(isinstance(item, dict) for item in entries):
        entries = sorted(entries, key=lambda item: int(item.get("number") or 0))
        return [str(item.get("path") or "") for item in entries if item.get("path")]
    return [str(item) for item in entries if str(item)]


def _probe_zip_view(view, eocd_offset: int, max_cd_entries_to_walk: int) -> dict:
    result = _probe_base("zip", eocd_offset)
    result.update({
        "eocd_offset": eocd_offset,
        "archive_offset": 0,
        "segment_end": 0,
        "central_directory_offset": 0,
        "central_directory_size": 0,
        "total_entries": 0,
        "central_directory_present": False,
        "central_directory_walk_ok": False,
        "central_directory_entries_checked": 0,
        "local_header_links_ok": False,
        "local_header_links_checked": 0,
    })
    eocd = view.read_at(eocd_offset, 22)
    if len(eocd) < 22 or eocd[:4] != b"PK\x05\x06":
        result["error"] = "bad_eocd_signature"
        return result
    result["magic_matched"] = True
    disk_number = _u16(eocd, 4)
    central_directory_disk = _u16(eocd, 6)
    disk_entries = _u16(eocd, 8)
    total_entries = _u16(eocd, 10)
    cd_size = _u32(eocd, 12)
    cd_offset = _u32(eocd, 16)
    comment_length = _u16(eocd, 20)
    segment_end = eocd_offset + 22 + comment_length
    result.update({"segment_end": segment_end, "central_directory_size": cd_size, "total_entries": total_entries})
    if disk_number != 0 or central_directory_disk != 0 or disk_entries != total_entries:
        result["error"] = "multi_disk_or_entry_mismatch"
        return result
    if eocd_offset < cd_size:
        result["error"] = "central_directory_size_out_of_range"
        return result
    physical_cd = eocd_offset - cd_size
    if physical_cd < cd_offset:
        result["error"] = "archive_offset_underflow"
        return result
    archive_offset = physical_cd - cd_offset
    result.update({"archive_offset": archive_offset, "central_directory_offset": physical_cd})
    if view.read_at(physical_cd, 4) != b"PK\x01\x02":
        result["error"] = "bad_central_directory_signature"
        return result
    result["central_directory_present"] = True
    entries, cd_ok, links, links_ok, error = _walk_zip_cd(view, archive_offset, physical_cd, cd_size, total_entries, max_cd_entries_to_walk)
    result.update({
        "central_directory_entries_checked": entries,
        "central_directory_walk_ok": cd_ok,
        "local_header_links_checked": links,
        "local_header_links_ok": links_ok,
        "error": error,
    })
    if not error:
        result["plausible"] = True
        result["evidence"] = ["zip:eocd", "zip:central_directory", "zip:central_directory_walk", "zip:local_header_links"]
    return result


def _walk_zip_cd(view, archive_offset: int, cd_offset: int, cd_size: int, total_entries: int, max_entries: int):
    cursor = cd_offset
    end = cd_offset + cd_size
    limit = min(total_entries, max_entries)
    links_checked = 0
    for index in range(limit):
        header = view.read_at(cursor, 46)
        if len(header) < 46 or header[:4] != b"PK\x01\x02":
            return index, False, links_checked, False, "bad_central_directory_entry_signature"
        filename_len = _u16(header, 28)
        extra_len = _u16(header, 30)
        comment_len = _u16(header, 32)
        local_header_offset = _u32(header, 42)
        entry_size = 46 + filename_len + extra_len + comment_len
        if cursor + entry_size > end:
            return index, False, links_checked, False, "central_directory_variable_fields_out_of_range"
        if view.read_at(archive_offset + local_header_offset, 4) != b"PK\x03\x04":
            return index + 1, True, links_checked, False, "local_header_link_mismatch"
        links_checked += 1
        cursor += entry_size
    return limit, True, links_checked, True, ""


def _probe_seven_zip_view(view, start_offset: int, max_next_header_check_bytes: int) -> dict:
    result = _probe_base("7z", start_offset)
    result.update({
        "archive_offset": start_offset,
        "segment_end": 0,
        "next_header_offset": 0,
        "next_header_size": 0,
        "start_header_crc_ok": False,
        "next_header_crc_checked": False,
        "next_header_crc_ok": False,
        "next_header_nid": 0,
        "next_header_nid_valid": False,
    })
    header = view.read_at(start_offset, 32)
    if len(header) < 32 or header[:6] != b"7z\xbc\xaf\x27\x1c":
        result["error"] = "7z_signature_not_found"
        return result
    result["magic_matched"] = True
    start_header = header[12:32]
    result["start_header_crc_ok"] = _u32(header, 8) == crc32(start_header) & 0xFFFFFFFF
    if not result["start_header_crc_ok"]:
        result["error"] = "start_header_crc_mismatch"
        return result
    next_offset = _u64(start_header, 0)
    next_size = _u64(start_header, 8)
    next_crc = _u32(start_header, 16)
    next_start = start_offset + 32 + next_offset
    segment_end = next_start + next_size
    result.update({"next_header_offset": next_offset, "next_header_size": next_size, "segment_end": segment_end})
    if next_size == 0 or next_start < start_offset + 32 or segment_end < next_start or segment_end > view.size:
        result["segment_end"] = 0
        result["error"] = "next_header_out_of_range"
        return result
    result["plausible"] = True
    result["evidence"] = ["7z:signature", "7z:start_header_crc", "7z:next_header_range"]
    if next_size <= max_next_header_check_bytes:
        next_header = view.read_at(next_start, next_size)
        crc_ok = crc32(next_header) & 0xFFFFFFFF == next_crc
        nid = next_header[0] if next_header else 0
        nid_valid = nid in (0x01, 0x17)
        result.update({
            "next_header_crc_checked": True,
            "next_header_crc_ok": crc_ok,
            "next_header_nid": nid,
            "next_header_nid_valid": nid_valid,
        })
        if crc_ok:
            result["evidence"].append("7z:next_header_crc")
            if nid_valid:
                result["strong_accept"] = True
                result["evidence"].append("7z:next_header_nid")
            else:
                result["error"] = "next_header_nid_unrecognized"
        else:
            result["error"] = "next_header_crc_mismatch"
    return result


def _probe_rar_view(view, start_offset: int, max_blocks: int) -> dict:
    result = _probe_base("rar", start_offset)
    result.update({"archive_offset": start_offset, "segment_end": 0, "version": 0, "blocks_checked": 0, "end_block_found": False})
    header = view.read_at(start_offset, 8)
    if header.startswith(b"Rar!\x1a\x07\x01\x00"):
        result.update({"magic_matched": True, "version": 5})
        return _probe_rar5_view(view, result, start_offset, max_blocks)
    if header.startswith(b"Rar!\x1a\x07\x00"):
        result.update({"magic_matched": True, "version": 4})
        return _probe_rar4_view(view, result, start_offset, max_blocks)
    result["error"] = "rar_signature_not_found"
    return result


def _probe_rar4_view(view, result: dict, start_offset: int, max_blocks: int) -> dict:
    cursor = start_offset + 7
    evidence = ["rar4:signature"]
    for index in range(max_blocks):
        fixed = view.read_at(cursor, 7)
        if len(fixed) < 7:
            result.update({"blocks_checked": index, "error": "rar4_block_header_out_of_range"})
            return result
        header_crc = _u16(fixed, 0)
        header_type = fixed[2]
        flags = _u16(fixed, 3)
        header_size = _u16(fixed, 5)
        full = view.read_at(cursor, header_size)
        if header_size < 7 or len(full) < header_size:
            result.update({"blocks_checked": index, "error": "rar4_block_size_out_of_range"})
            return result
        if crc32(full[2:]) & 0xFFFF != header_crc:
            result.update({"blocks_checked": index, "error": "rar4_block_crc_mismatch"})
            return result
        block_size = header_size + (_u32(full, 7) if flags & 0x8000 and header_size >= 11 else 0)
        if index == 0 and header_type != 0x73:
            result.update({"blocks_checked": 1, "error": "rar4_main_header_missing"})
            return result
        if index == 0:
            evidence.append("rar4:main_header")
        cursor += block_size
        if header_type == 0x7B:
            result.update({"plausible": True, "strong_accept": True, "blocks_checked": index + 1, "end_block_found": True, "segment_end": cursor, "evidence": evidence + ["rar4:end_block"], "error": ""})
            return result
    result.update({"plausible": True, "blocks_checked": max_blocks, "segment_end": cursor, "evidence": evidence, "error": "rar4_block_walk_limit_reached"})
    return result


def _probe_rar5_view(view, result: dict, start_offset: int, max_blocks: int) -> dict:
    cursor = start_offset + 8
    evidence = ["rar5:signature"]
    for index in range(max_blocks):
        head = view.read_at(cursor, 64)
        if len(head) < 6:
            result.update({"blocks_checked": index, "error": "rar5_block_header_out_of_range"})
            return result
        parsed = _read_vint(head, 4)
        if parsed is None:
            result.update({"blocks_checked": index, "error": "rar5_header_size_vint_missing"})
            return result
        header_size, after_size = parsed
        total = 4 + (after_size - 4) + header_size
        full = view.read_at(cursor, total)
        if header_size <= 0 or len(full) < total:
            result.update({"blocks_checked": index, "error": "rar5_header_size_out_of_range"})
            return result
        parsed_type = _read_vint(full, after_size)
        parsed_flags = _read_vint(full, parsed_type[1]) if parsed_type else None
        if not parsed_type or not parsed_flags:
            result.update({"blocks_checked": index, "error": "rar5_header_fields_vint_missing"})
            return result
        header_type, _ = parsed_type
        flags, field_cursor = parsed_flags
        if crc32(full[4:]) & 0xFFFFFFFF != _u32(full, 0):
            result.update({"blocks_checked": index, "error": "rar5_block_crc_mismatch"})
            return result
        if flags & 0x0001:
            parsed_extra = _read_vint(full, field_cursor)
            if not parsed_extra:
                result.update({"blocks_checked": index, "error": "rar5_extra_area_size_vint_missing"})
                return result
            _, field_cursor = parsed_extra
        data_size = 0
        if flags & 0x0002:
            parsed_data = _read_vint(full, field_cursor)
            if not parsed_data:
                result.update({"blocks_checked": index, "error": "rar5_data_size_vint_missing"})
                return result
            data_size, _ = parsed_data
        if index == 0 and header_type != 1:
            result.update({"blocks_checked": 1, "error": "rar5_main_header_missing"})
            return result
        if index == 0:
            evidence.append("rar5:main_header")
        cursor += total + data_size
        if header_type == 5:
            result.update({"plausible": True, "strong_accept": True, "blocks_checked": index + 1, "end_block_found": True, "segment_end": cursor, "evidence": evidence + ["rar5:end_block"], "error": ""})
            return result
    result.update({"plausible": True, "blocks_checked": max_blocks, "segment_end": cursor, "evidence": evidence, "error": "rar5_block_walk_limit_reached"})
    return result


def _probe_base(fmt: str, start_offset: int) -> dict:
    return {"format": fmt, "plausible": False, "magic_matched": False, "strong_accept": False, "error": "", "archive_offset": start_offset, "evidence": []}


def _probe_tar_view(view, start_offset: int, max_entries: int) -> dict:
    result = _probe_base("tar", start_offset)
    cursor = start_offset
    entries = 0
    for _ in range(max_entries):
        block = view.read_at(cursor, 512)
        if len(block) < 512:
            result["error"] = "tar_header_out_of_range"
            break
        if block == b"\x00" * 512:
            next_block = view.read_at(cursor + 512, 512)
            result.update({
                "magic_matched": entries > 0,
                "plausible": entries > 0,
                "strong_accept": entries > 0 and next_block == b"\x00" * 512,
                "end_zero_blocks": next_block == b"\x00" * 512,
                "entries_checked": entries,
                "segment_end": cursor + (1024 if next_block == b"\x00" * 512 else 512),
                "evidence": ["tar:header", "tar:end_zero_blocks"] if entries > 0 else [],
                "error": "",
            })
            return result
        if block[257:262] != b"ustar":
            result["error"] = "tar_ustar_not_found" if entries == 0 else "tar_next_header_missing"
            break
        entries += 1
        size = _tar_octal(block[124:136])
        data_blocks = (size + 511) // 512
        cursor += 512 + data_blocks * 512
    result.update({
        "magic_matched": entries > 0,
        "plausible": entries > 0,
        "entries_checked": entries,
        "segment_end": cursor if entries else 0,
        "evidence": ["tar:header"] if entries else [],
    })
    return result


def _probe_compression_stream_view(view, fmt: str) -> dict:
    signatures = {
        "gzip": b"\x1f\x8b\x08",
        "bzip2": b"BZh",
        "xz": b"\xfd7zXZ\x00",
        "zstd": b"\x28\xb5\x2f\xfd",
    }
    signature = signatures.get(fmt, b"")
    head = view.read_at(0, max(8, len(signature)))
    matched = bool(signature and head.startswith(signature))
    return {
        "format": fmt,
        "magic_matched": matched,
        "plausible": matched,
        "confidence": 0.78 if matched else 0.0,
        "evidence": [f"{fmt}:signature"] if matched else [],
        "error": "" if matched else "signature_not_found",
    }


def _tar_octal(data: bytes) -> int:
    text = data.split(b"\x00", 1)[0].strip() or b"0"
    try:
        return int(text, 8)
    except ValueError:
        return 0


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _byte_class(data: bytes) -> dict:
    if not data:
        return {"printable_ratio": 0.0, "zero_ratio": 0.0, "ff_ratio": 0.0}
    total = len(data)
    printable = sum(1 for byte in data if byte in (9, 10, 13) or 32 <= byte <= 126)
    return {
        "printable_ratio": printable / total,
        "zero_ratio": data.count(0) / total,
        "ff_ratio": data.count(0xFF) / total,
    }


def _run_profile(data: bytes, base_offset: int) -> dict:
    zero = _longest_run(data, 0, base_offset)
    ff = _longest_run(data, 0xFF, base_offset)
    tail = zero if zero.get("offset", 0) + zero.get("length", 0) >= base_offset + len(data) else {}
    return {
        "longest_zero_run": zero,
        "longest_ff_run": ff,
        "tail_run": tail,
        "tail_padding_likely": int(tail.get("length", 0) or 0) >= 1024,
    }


def _longest_run(data: bytes, value: int, base_offset: int) -> dict:
    best_offset = 0
    best_length = 0
    current_offset = 0
    current_length = 0
    for index, byte in enumerate(data):
        if byte == value:
            if current_length == 0:
                current_offset = index
            current_length += 1
            if current_length > best_length:
                best_offset = current_offset
                best_length = current_length
        else:
            current_length = 0
    return {"offset": base_offset + best_offset, "length": best_length}


def _byte_histogram(data: bytes, top_k: int) -> list[dict]:
    return [
        {"byte": byte, "count": count}
        for byte, count in Counter(data).most_common(max(1, int(top_k)))
    ]


_KNOWN_SIGNATURES = {
    "zip_local": b"PK\x03\x04",
    "zip_eocd": b"PK\x05\x06",
    "rar4": b"Rar!\x1a\x07\x00",
    "rar5": b"Rar!\x1a\x07\x01\x00",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "gzip": b"\x1f\x8b\x08",
    "bzip2": b"BZh",
    "xz": b"\xfd7zXZ\x00",
    "zstd": b"\x28\xb5\x2f\xfd",
    "tar_ustar": b"ustar",
}


def _find_all(data: bytes, needle: bytes):
    start = 0
    while True:
        index = data.find(needle, start)
        if index < 0:
            return
        yield index
        start = index + 1


def _formats_from_hits(hits: list[dict]) -> set[str]:
    formats = set()
    for hit in hits:
        name = str(hit.get("name") or "")
        if name.startswith("zip_"):
            formats.add("zip")
        elif name.startswith("rar"):
            formats.add("rar")
        elif name == "7z":
            formats.add("7z")
        elif name == "gzip":
            formats.add("gzip")
        elif name == "bzip2":
            formats.add("bzip2")
        elif name == "xz":
            formats.add("xz")
        elif name == "zstd":
            formats.add("zstd")
        elif name == "tar_ustar":
            formats.add("tar")
    return formats


def _read_vint(data: bytes, offset: int):
    value = 0
    shift = 0
    for index in range(offset, min(len(data), offset + 10)):
        byte = data[index]
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, index + 1
        shift += 7
    return None


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 8], "little")
