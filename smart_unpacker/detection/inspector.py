from __future__ import annotations

import os
import re
import subprocess
import zipfile

from .signatures import MAGICS, TAIL_MAGICS, WEAK_MAGICS
from smart_unpacker.support.types import InspectionResult


class ArchiveInspector:
    STREAM_CHUNK_SIZE = 1024 * 1024

    def __init__(self, engine):
        self.engine = engine
        self.inspect_cache = {}
        self.validation_cache = {}
        self.probe_cache = {}
        self.MAGICS = MAGICS
        self.WEAK_MAGICS = WEAK_MAGICS
        self.TAIL_MAGICS = TAIL_MAGICS
        self.CARRIER_TAIL_DETECTORS = {
            ".jpg": self._find_embedded_archive_after_jpeg,
            ".jpeg": self._find_embedded_archive_after_jpeg,
            ".png": self._find_embedded_archive_after_png,
            ".pdf": self._find_embedded_archive_after_pdf,
            ".gif": self._find_embedded_archive_after_gif,
            ".webp": self._find_embedded_archive_after_webp,
        }
        self.CARRIER_EXTS = set(self.CARRIER_TAIL_DETECTORS)
        self.EXECUTABLE_PROBE_TYPES = {"pe", "elf", "macho", "te"}

    def clear_caches(self):
        self.inspect_cache.clear()
        self.validation_cache.clear()
        self.probe_cache.clear()

    def _make_inspection(self, path):
        return InspectionResult(path=path)

    def _add_reason(self, info, score_delta, reason):
        info.score += score_delta
        info.reasons.append(f"{score_delta:+d} {reason}")

    def _classify_zip_container(self, path):
        lower_name = os.path.basename(path).lower()
        _, ext = os.path.splitext(lower_name)
        if ext in self.engine.ZIP_CONTAINER_EXTS:
            return ext
        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = {name.lower() for name in zf.namelist()[:200]}
        except Exception:
            return None
        if "meta-inf/manifest.mf" in names:
            return ".jar"
        if "[content_types].xml" in names and "word/document.xml" in names:
            return ".docx"
        if "[content_types].xml" in names and "xl/workbook.xml" in names:
            return ".xlsx"
        if "androidmanifest.xml" in names and "classes.dex" in names:
            return ".apk"
        return None

    def _validate_with_7z(self, path):
        norm_path = os.path.normpath(path)
        cached = self.validation_cache.get(norm_path)
        if cached is not None:
            return cached

        si = self.engine._make_startupinfo()
        cmd = [self.engine.seven_z_path, "t", norm_path, "-y"]
        rt = subprocess.run(cmd, capture_output=True, text=True, startupinfo=si, stdin=subprocess.DEVNULL)
        err = f"{rt.stdout}\n{rt.stderr}".lower()
        result = {
            "ok": rt.returncode == 0,
            "encrypted": "wrong password" in err or "cannot open encrypted archive" in err,
            "error_text": err,
        }
        self.validation_cache[norm_path] = result
        return result

    def _probe_archive_with_7z(self, path):
        norm_path = os.path.normpath(path)
        cached = self.probe_cache.get(norm_path)
        if cached is not None:
            return cached

        si = self.engine._make_startupinfo()
        cmd = [self.engine.seven_z_path, "l", "-slt", norm_path]
        rt = subprocess.run(cmd, capture_output=True, text=True, startupinfo=si, stdin=subprocess.DEVNULL)
        out = f"{rt.stdout}\n{rt.stderr}"
        lower = out.lower()
        archive_type = None
        for line in out.splitlines():
            if line.lower().startswith("type = "):
                archive_type = line.split("=", 1)[1].strip().lower()
                break
        result = {
            "is_archive": False,
            "type": archive_type,
            "offset": 0,
            "is_encrypted": False,
            "is_broken": False,
        }
        if rt.returncode == 0:
            result["is_archive"] = archive_type not in self.EXECUTABLE_PROBE_TYPES if archive_type else True
            result["is_encrypted"] = "encrypted = +" in lower
        else:
            if archive_type:
                result["is_archive"] = True
            type_match = re.search(r"open the file as \[([^\]]+)\] archive", lower)
            if type_match:
                result["type"] = type_match.group(1).strip().lower()
                result["is_archive"] = True
            result["is_encrypted"] = "wrong password" in lower or "cannot open encrypted archive" in lower
            if not result["is_archive"] and "listing archive:" in lower and "enter password" in lower:
                result["is_archive"] = True
                result["is_encrypted"] = True
            result["is_broken"] = self.engine._has_archive_damage_signals(lower)

        m = re.search(r"offset = (\d+)", lower)
        if m:
            result["offset"] = int(m.group(1))
        self.probe_cache[norm_path] = result
        return result

    def _apply_size_and_extension_signals(self, info, ext):
        if info.size >= self.engine.MIN_SIZE:
            self._add_reason(info, +1, f"大文件({info.size // (1024 * 1024)}MB)")
        if ext in self.engine.STANDARD_EXTS:
            self._add_reason(info, +4, "标准归档扩展名")
        elif ext in self.engine.ZIP_CONTAINER_EXTS:
            self._add_reason(info, -4, "ZIP 语义容器扩展名，默认不视为待解压包")
        elif ext in self.engine.AMBIGUOUS_RESOURCE_EXTS:
            self._add_reason(info, -1, "资源类易混淆扩展名")

    def _should_skip_all_checks_by_size(self, info):
        return info.size < self.engine.MIN_SIZE

    def _detect_signature(self, info, sig):
        for magic, detected_ext in self.MAGICS.items():
            if sig.startswith(magic):
                info.magic_matched = True
                info.detected_ext = detected_ext
                self._add_reason(info, +5, f"文件头命中 {detected_ext} 魔数")
                return
        for magic, detected_ext in self.WEAK_MAGICS.items():
            if sig.startswith(magic):
                info.detected_ext = detected_ext
                self._add_reason(info, -1, f"弱魔数命中 {detected_ext}")
                return

    def _apply_magic_analysis(self, info, norm_path):
        if info.detected_ext == ".zip":
            zip_container = self._classify_zip_container(norm_path)
            if zip_container:
                info.container_type = zip_container.lstrip(".")
                self._add_reason(info, -5, f"识别为 ZIP 语义容器 {zip_container}")

    def _match_tail_magic(self, sample, offset):
        for magic, detected_ext in self.TAIL_MAGICS.items():
            index = sample.find(magic, offset)
            if index != -1:
                return detected_ext, index
        return None, -1

    def _stream_find_tail_magic_from_offset(self, norm_path, absolute_offset):
        if absolute_offset < 0:
            absolute_offset = 0
        max_tail_len = max((len(magic) for magic in self.TAIL_MAGICS), default=0)
        overlap = max(max_tail_len - 1, 0)
        with open(norm_path, "rb") as handle:
            handle.seek(absolute_offset)
            carry = b""
            current_offset = absolute_offset
            while True:
                chunk = handle.read(self.STREAM_CHUNK_SIZE)
                if not chunk:
                    return None
                sample = carry + chunk
                base_offset = current_offset - len(carry)
                detected_ext, relative_index = self._match_tail_magic(sample, 0)
                if detected_ext:
                    return {"detected_ext": detected_ext, "offset": base_offset + relative_index}
                if len(sample) > overlap:
                    carry = sample[-overlap:]
                else:
                    carry = sample
                current_offset += len(chunk)

    def _stream_find_tail_after_markers(self, norm_path, markers):
        markers = tuple(marker for marker in markers if marker)
        if not markers:
            return None
        max_marker_len = max(len(marker) for marker in markers)
        max_tail_len = max((len(magic) for magic in self.TAIL_MAGICS), default=0)
        overlap = max(max_marker_len, max_tail_len) - 1
        with open(norm_path, "rb") as handle:
            carry = b""
            current_offset = 0
            while True:
                chunk = handle.read(self.STREAM_CHUNK_SIZE)
                if not chunk:
                    return None
                sample = carry + chunk
                base_offset = current_offset - len(carry)

                first_match = None
                for marker in markers:
                    index = sample.find(marker)
                    if index != -1 and (first_match is None or index < first_match[1]):
                        first_match = (marker, index)

                if first_match is not None:
                    marker, marker_index = first_match
                    search_start = marker_index + len(marker)
                    detected_ext, relative_index = self._match_tail_magic(sample, search_start)
                    if detected_ext:
                        return {"detected_ext": detected_ext, "offset": base_offset + relative_index}
                    return self._stream_find_tail_magic_from_offset(norm_path, base_offset + search_start)

                if len(sample) > overlap:
                    carry = sample[-overlap:]
                else:
                    carry = sample
                current_offset += len(chunk)

    def _find_embedded_archive_after_jpeg(self, sample):
        eoi = sample.find(b"\xff\xd9")
        if eoi == -1:
            return None
        return self._match_tail_magic(sample, eoi + 2)

    def _find_embedded_archive_after_png(self, sample):
        marker = b"IEND\xaeB`\x82"
        eoi = sample.find(marker)
        if eoi == -1:
            return None
        return self._match_tail_magic(sample, eoi + len(marker))

    def _find_embedded_archive_after_pdf(self, sample):
        for marker in (b"%%EOF\r\n", b"%%EOF\n", b"%%EOF"):
            eoi = sample.find(marker)
            if eoi != -1:
                return self._match_tail_magic(sample, eoi + len(marker))
        return None

    def _find_embedded_archive_after_gif(self, sample):
        eoi = sample.find(b"\x3b")
        if eoi == -1:
            return None
        return self._match_tail_magic(sample, eoi + 1)

    def _find_embedded_archive_after_webp(self, sample):
        if len(sample) < 12 or not sample.startswith(b"RIFF") or sample[8:12] != b"WEBP":
            return None
        riff_size = int.from_bytes(sample[4:8], "little")
        payload_end = 8 + riff_size
        if payload_end >= len(sample):
            return None
        return self._match_tail_magic(sample, payload_end)

    def _find_embedded_archive_after_carrier(self, norm_path, ext):
        if ext in {".jpg", ".jpeg"}:
            return self._stream_find_tail_after_markers(norm_path, (b"\xff\xd9",))
        if ext == ".png":
            return self._stream_find_tail_after_markers(norm_path, (b"IEND\xaeB`\x82",))
        if ext == ".pdf":
            return self._stream_find_tail_after_markers(norm_path, (b"%%EOF\r\n", b"%%EOF\n", b"%%EOF"))
        if ext == ".gif":
            return self._stream_find_tail_after_markers(norm_path, (b"\x3b",))
        if ext == ".webp":
            with open(norm_path, "rb") as handle:
                header = handle.read(12)
            if len(header) < 12 or not header.startswith(b"RIFF") or header[8:12] != b"WEBP":
                return None
            riff_size = int.from_bytes(header[4:8], "little")
            payload_end = 8 + riff_size
            return self._stream_find_tail_magic_from_offset(norm_path, payload_end)
        detector = self.CARRIER_TAIL_DETECTORS.get(ext)
        if detector is None:
            return None
        with open(norm_path, "rb") as f:
            sample = f.read()
        result = detector(sample)
        if not result:
            return None
        detected_ext, index = result
        if not detected_ext:
            return None
        return {"detected_ext": detected_ext, "offset": index}

    def _apply_embedded_tail_analysis(self, info, ext, norm_path):
        if ext not in self.CARRIER_EXTS:
            return
        embedded = self._find_embedded_archive_after_carrier(norm_path, ext)
        if not embedded:
            return
        info.detected_ext = embedded["detected_ext"]
        info.probe_detected_archive = True
        info.probe_offset = embedded["offset"]
        self._add_reason(info, +5, f"载体文件尾部检测到嵌入式 {embedded['detected_ext']} 归档")

    def _apply_probe_analysis(self, info, ext, norm_path):
        if not self._should_probe_with_7z(info, ext, norm_path):
            return
        probe = self.engine._probe_archive_with_7z(norm_path)
        probe_type = probe["type"]
        if probe_type in self.EXECUTABLE_PROBE_TYPES:
            info.container_type = probe_type
            self._add_reason(info, -3, f"7z 深度探测识别为可执行容器 {probe_type}")
            return
        if not probe["is_archive"]:
            if not probe["is_broken"] and not probe["is_encrypted"]:
                self._add_reason(info, -3, "7z 深度探测未识别为归档")
            return
        info.probe_detected_archive = True
        info.probe_offset = probe["offset"]
        if probe_type:
            info.detected_ext = "." + probe_type if not probe_type.startswith(".") else probe_type
        self._add_reason(info, +5, "7z 深度探测识别为归档")
        if ext not in self.engine.STANDARD_EXTS:
            self._add_reason(info, +2, "非归档扩展名中检测到隐藏归档")
        if probe["is_encrypted"]:
            self._add_reason(info, +1, "归档头已加密，但可被识别")
        if probe["offset"] and probe["offset"] > 0:
            self._add_reason(info, +2, f"检测到嵌入式归档偏移 {probe['offset']}")
        if ext == ".exe":
            self._add_reason(info, +2, "EXE 容器中识别到自解压归档")
        if probe["is_broken"]:
            self._add_reason(info, +1, "归档结构损坏，但可被识别")

    def _apply_disguise_signal(self, info, ext):
        if ext != info.detected_ext and info.detected_ext and ext not in self.engine.STANDARD_EXTS:
            self._add_reason(info, +3, "扩展名与内容不一致，疑似伪装包")
        if ext in self.engine.STRICT_SEMANTIC_SKIP_EXTS and info.detected_ext and not info.probe_detected_archive:
            self._add_reason(info, -6, "语义保护后缀优先，不按通用压缩包处理")

    def _looks_like_disguised_archive_name(self, filename):
        lower_name = filename.lower()
        return any(
            re.search(pattern, lower_name, re.I)
            for pattern in (
                r"\.(7z|rar|zip|gz|bz2|xz)\.[^.]+$",
                r"\.exe\.[^.]+$",
                r"\.(7z|zip|rar)\.001(?:\.[^.]+)?$",
                r"\.part\d+\.rar(?:\.[^.]+)?$",
                r"\.\d{3}(?:\.[^.]+)?$",
            )
        )

    def _should_probe_with_7z(self, info, ext, norm_path):
        if info.magic_matched:
            return False
        if info.size < self.engine.MIN_SIZE:
            return False
        if ext in self.engine.STRICT_SEMANTIC_SKIP_EXTS and not info.is_split_candidate:
            return False
        if ext in self.engine.LIKELY_RESOURCE_EXTS and not info.is_split_candidate:
            return False
        if info.is_split_candidate:
            return True
        if ext in self.engine.STANDARD_EXTS:
            return True
        if ext == ".exe" or info.detected_ext == ".exe":
            return True
        if self._looks_like_disguised_archive_name(os.path.basename(norm_path)):
            return True
        if not ext and info.size >= self.engine.MIN_SIZE * 2:
            return True
        return False

    def _apply_split_signals(self, info, norm_path, ext):
        filename = os.path.basename(norm_path)
        split_role = self.engine.relation_builder.detect_filename_split_role(filename)
        if split_role == "first":
            info.is_split_candidate = True
            self._add_reason(info, +3, "疑似首个分卷")
        elif split_role == "member":
            info.is_split_candidate = True
            self._add_reason(info, +1, "疑似分卷成员")

        if ext == ".exe" and not info.is_split_candidate and not info.probe_detected_archive:
            self._add_reason(info, -2, "独立 EXE 文件默认跳过")

    def _apply_validation_signal(self, info, ext, norm_path):
        if not self._should_validate_with_7z(info, ext):
            info.validation_skipped = self._should_mark_validation_skipped(info, ext)
            return
        validation = self.engine._validate_with_7z(norm_path)
        info.validation_ok = validation["ok"]
        info.validation_skipped = False
        info.validation_encrypted = validation["encrypted"]
        if validation["ok"]:
            self._add_reason(info, +3, "7z 测试通过")
        elif validation["encrypted"]:
            self._add_reason(info, +1, "7z 测试命中加密归档")
        else:
            self._add_reason(info, -1, "7z 测试未通过")

    def _should_mark_validation_skipped(self, info, ext):
        return (
            ext in self.engine.STANDARD_EXTS
            and info.magic_matched
            and not info.is_split_candidate
            and not info.probe_detected_archive
            and info.detected_ext == ext
        )

    def _should_validate_with_7z(self, info, ext):
        if self._should_mark_validation_skipped(info, ext):
            return False
        should_validate = (
            info.probe_detected_archive
            or info.magic_matched
            or ext in self.engine.STANDARD_EXTS
            or info.is_split_candidate
            or info.score >= self.engine.ARCHIVE_SCORE_THRESHOLD
        )
        if not should_validate:
            return False
        if ext in self.engine.LIKELY_RESOURCE_EXTS and not (
            info.probe_detected_archive or info.magic_matched or info.is_split_candidate
        ):
            return False
        return True

    def _finalize_inspection_decision(self, info, ext):
        if info.scene_role == "embedded_resource_archive":
            info.decision = "not_archive"
            info.should_extract = False
            return

        semantic_skip_hard_stop = ext in self.engine.STRICT_SEMANTIC_SKIP_EXTS and not info.is_split_candidate
        if semantic_skip_hard_stop:
            info.decision = "not_archive"
            info.should_extract = False
            info.reasons.append("+0 强语义保护命中，禁止按通用压缩包处理")
        elif info.is_split_candidate and not (
            info.magic_matched or info.probe_detected_archive or info.validation_ok or info.validation_encrypted
        ):
            if info.score >= self.engine.MAYBE_ARCHIVE_THRESHOLD:
                info.decision = "maybe_archive"
            else:
                info.decision = "not_archive"
            info.should_extract = False
        elif info.score >= self.engine.ARCHIVE_SCORE_THRESHOLD:
            info.decision = "archive"
            info.should_extract = True
        elif info.score >= self.engine.MAYBE_ARCHIVE_THRESHOLD:
            info.decision = "maybe_archive"
        else:
            info.decision = "not_archive"

    def inspect_archive_candidate(self, path, relation=None, scene_context=None):
        norm_path = os.path.normpath(path)
        scene_cache_key = scene_context.target_dir if scene_context else None
        cache_key = (norm_path, scene_cache_key)
        cached = self.inspect_cache.get(cache_key)
        if cached is not None:
            return cached

        info = self._make_inspection(norm_path)
        try:
            info.size = os.path.getsize(norm_path)
            _, ext = os.path.splitext(norm_path)
            ext = ext.lower()
            info.ext = ext
            if self._should_skip_all_checks_by_size(info):
                info.skipped_by_size_limit = True
                info.reasons.append(
                    f"+0 文件小于最小检测大小阈值({self.engine.MIN_SIZE} bytes)，跳过后续检查"
                )
                self.inspect_cache[cache_key] = info
                return info
            self._apply_size_and_extension_signals(info, ext)

            with open(norm_path, "rb") as f:
                sig = f.read(8)
            self._detect_signature(info, sig)
            self._apply_magic_analysis(info, norm_path)
            self._apply_embedded_tail_analysis(info, ext, norm_path)
            if not info.magic_matched:
                self._apply_probe_analysis(info, ext, norm_path)
            self._apply_disguise_signal(info, ext)
            self._apply_split_signals(info, norm_path, ext)
            self._apply_validation_signal(info, ext, norm_path)
            self.engine.scene_analyzer.apply_scene_semantics(info, relation, scene_context)
            self._finalize_inspection_decision(info, ext)
        except Exception as e:
            info.decision = "not_archive"
            info.should_extract = False
            info.reasons.append(f"-99 检查失败: {e}")

        self.inspect_cache[cache_key] = info
        return info
