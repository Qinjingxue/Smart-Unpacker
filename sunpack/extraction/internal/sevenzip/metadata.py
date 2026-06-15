import os
import re
from typing import List, Optional, Tuple, Dict, Any

from sunpack_native import scan_zip_central_directory_names as _NATIVE_SCAN_ZIP_NAMES

class ArchiveMetadataScanResult:
    def __init__(self, archive_path: str, archive_type: str, reasons: List[str] = None):
        self.archive_path = archive_path
        self.archive_type = archive_type
        self.warnings: List[str] = []
        self.reasons: List[str] = reasons or []
        self.selected_codepage: Optional[str] = None
        self.decoded_names: List[str] = []
        self.error: Optional[str] = None
        self.confidence: float = 0.0
        self.sample_count: int = 0

class ArchiveMetadataScanner:
    MAX_ZIP_SAMPLES = 200000
    MAX_FILENAME_BYTES = 64 * 1024 * 1024
    LIST_TIMEOUT_SECONDS = 5

    CODEPAGE_CANDIDATES = (
        ("cp437", None, "ZIP default cp437"),
        ("utf-8", "65001", "UTF-8"),
        ("cp936", "936", "GBK/CP936"),
        ("cp950", "950", "Big5/CP950"),
        ("cp932", "932", "Shift-JIS/CP932"),
    )
    SIMPLIFIED_COMMON_CHARS = set("的一是在不了有和人这中大为上个国我以要他中文说明资料第一章压缩文件测试")
    TRADITIONAL_COMMON_CHARS = set("的一是在不了有和人這中大為上個國我以要他繁體中文說明資料檔案測試")
    JAPANESE_COMMON_KANJI = set(
        "日本語説明書第一章画像映像音声写真漫画小説資料設定保存読込名前新旧上下左右"
        "大小年月日時分秒人子女男学校会社仕事場所東京大阪京都北海道"
    )

    def __init__(self):
        self.cache = {}

    def clear_caches(self):
        self.cache.clear()

    def scan(self, archive_path: str, password: Optional[str] = None, part_paths: list[str] | None = None) -> ArchiveMetadataScanResult:
        archive_path = os.path.normpath(archive_path)
        cache_key = self._build_cache_key(archive_path, part_paths=part_paths)
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        result = self._scan_uncached(archive_path, password=password, part_paths=part_paths)
        self.cache[cache_key] = result
        return result

    def _build_cache_key(self, archive_path: str, part_paths: list[str] | None = None) -> tuple:
        part_keys = []
        for path in list(dict.fromkeys(part_paths or [archive_path])):
            try:
                stat = os.stat(path)
                part_keys.append((path, stat.st_size, stat.st_mtime_ns))
            except OSError:
                part_keys.append((path, 0, 0))
        try:
            stat = os.stat(archive_path)
            return (archive_path, stat.st_size, stat.st_mtime_ns, tuple(part_keys))
        except OSError:
            return (archive_path, 0, 0, tuple(part_keys))

    def _scan_uncached(self, archive_path: str, password: Optional[str] = None, part_paths: list[str] | None = None) -> ArchiveMetadataScanResult:
        ext = os.path.splitext(archive_path)[1].lower()
        if ext == ".zip":
            return self._scan_zip_central_directory(archive_path)
        if ext in {".7z", ".rar"}:
            return ArchiveMetadataScanResult(
                archive_path=archive_path,
                archive_type=ext.lstrip("."),
                reasons=[f"{ext.lstrip('.').upper()} 解压前元数据扫描不需要编码修正，保持默认解压参数"],
            )
        return ArchiveMetadataScanResult(
            archive_path=archive_path,
            archive_type=ext.lstrip(".") or "unknown",
            reasons=["不支持的元数据编码扫描类型，保持默认解压参数"],
        )

    def _scan_zip_central_directory(self, archive_path: str) -> ArchiveMetadataScanResult:
        result = ArchiveMetadataScanResult(archive_path=archive_path, archive_type="zip")
        try:
            raw_names, utf8_flags, truncated, warning = self._scan_zip_name_samples(archive_path)
            if warning:
                result.warnings.append(warning)
                return result
            result.sample_count = len(raw_names)
            if truncated:
                result.error = "ZIP 文件名数量或总长度超过编码识别上限"
                result.warnings.append(result.error)
                return result
            if not raw_names:
                result.reasons.append("ZIP 中央目录没有可分析的文件名")
                return result
            if all(utf8_flags):
                result.reasons.append("ZIP 条目均带 UTF-8 标记，保持默认解压参数")
                return result
            if all(self._is_ascii_name(raw_name) for raw_name in raw_names):
                result.reasons.append("ZIP 文件名均为 ASCII，保持默认解压参数")
                return result

            unmarked_names = [raw_name for raw_name, utf8 in zip(raw_names, utf8_flags) if not utf8]
            selected = self._select_codepage(unmarked_names)
            result.confidence = selected["confidence"]
            result.reasons.extend(selected["reasons"])
            if selected["codepage"]:
                result.selected_codepage = selected["codepage"]
                result.decoded_names = self._decode_names(
                    raw_names,
                    utf8_flags,
                    selected["encoding"],
                )
                result.reasons.append(f"高置信选择 {selected['label']}，解压时按 CP{selected['codepage']} 覆盖 ZIP 条目路径")
            else:
                result.error = "ZIP 文件名编码置信度不足"
                result.reasons.append(result.error)
            return result
        except Exception as exc:
            result.warnings.append(f"ZIP 元数据扫描失败: {exc}")
            return result

    def _scan_zip_name_samples(self, archive_path: str) -> Tuple[List[bytes], List[bool], bool, str]:
        return self._scan_zip_name_samples_native(archive_path)

    def _scan_zip_name_samples_native(self, archive_path: str) -> Tuple[List[bytes], List[bool], bool, str]:
        result = _NATIVE_SCAN_ZIP_NAMES(
            archive_path,
            self.MAX_ZIP_SAMPLES,
            self.MAX_FILENAME_BYTES,
        )
        if not isinstance(result, dict):
            raise TypeError("Native ZIP name scanner returned a non-dict result")

        status = result.get("status")
        warning = self._zip_native_status_warning(status)
        if warning:
            return [], [], False, warning
        if status != "ok":
            raise RuntimeError(f"Native ZIP name scanner returned unsupported status: {status}")

        raw_names = result.get("raw_names")
        utf8_flags = result.get("utf8_flags")
        truncated = result.get("truncated")
        if not isinstance(raw_names, list) or not isinstance(truncated, bool):
            raise TypeError("Native ZIP name scanner returned invalid raw_names/truncated")
        if not isinstance(utf8_flags, list) or len(utf8_flags) != len(raw_names):
            raise TypeError("Native ZIP name scanner returned invalid utf8_flags")
        normalized_names = []
        normalized_flags = []
        for raw_name, utf8_flag in zip(raw_names, utf8_flags):
            if not isinstance(raw_name, bytes):
                raise TypeError("Native ZIP name scanner returned a non-bytes name")
            if not isinstance(utf8_flag, bool):
                raise TypeError("Native ZIP name scanner returned a non-bool UTF-8 flag")
            normalized_names.append(raw_name)
            normalized_flags.append(utf8_flag)
        return normalized_names, normalized_flags, truncated, ""

    @staticmethod
    def _decode_names(raw_names: List[bytes], utf8_flags: List[bool], encoding: str) -> List[str]:
        decoded = []
        for raw_name, utf8_flag in zip(raw_names, utf8_flags):
            codec = "utf-8" if utf8_flag else encoding
            decoded.append(raw_name.decode(codec, errors="strict").replace("\\", "/"))
        return decoded

    def _zip_native_status_warning(self, status) -> str:
        warnings = {
            "file_too_small": "ZIP 文件过小，无法读取 EOCD",
            "eocd_not_found": "未找到 ZIP EOCD，跳过编码修正",
            "eocd_incomplete": "ZIP EOCD 不完整，跳过编码修正",
            "zip64": "ZIP64 中央目录暂不做纯 Python 编码修正",
            "central_range_invalid": "ZIP 中央目录范围异常，跳过编码修正",
        }
        return warnings.get(status, "")

    def _select_codepage(self, raw_names: List[bytes]) -> Dict[str, Any]:
        scores = []
        for encoding, codepage, label in self.CODEPAGE_CANDIDATES:
            score, decoded_count, reasons = self._score_encoding(raw_names, encoding)
            scores.append(
                {
                    "encoding": encoding,
                    "codepage": codepage,
                    "label": label,
                    "score": score,
                    "decoded_count": decoded_count,
                    "reasons": reasons,
                }
            )

        scores.sort(key=lambda item: item["score"], reverse=True)
        best = scores[0]
        second = scores[1] if len(scores) > 1 else {"score": 0, "label": "-"}
        lead = best["score"] - second["score"]
        confidence = max(0.0, min(1.0, (lead + max(best["score"], 0)) / 60.0))
        reasons = [
            f"编码候选最高分: {best['label']}={best['score']}，次高: {second['label']}={second['score']}，领先={lead}",
        ]
        reasons.extend(best["reasons"][:3])

        if best["codepage"] and best["score"] >= 12 and lead >= 6 and best["decoded_count"] > 0:
            return {
                "encoding": best["encoding"],
                "codepage": best["codepage"],
                "confidence": round(confidence, 3),
                "label": best["label"],
                "reasons": reasons,
            }
        return {
            "encoding": best["encoding"],
            "codepage": None,
            "confidence": round(confidence, 3),
            "label": best["label"],
            "reasons": reasons,
        }

    def _score_encoding(self, raw_names: List[bytes], encoding: str) -> Tuple[int, int, List[str]]:
        score = 0
        decoded_count = 0
        total_cjk = 0
        total_kana = 0
        total_halfwidth_kana = 0
        total_latin_symbols = 0
        reasons = []

        for raw_name in raw_names:
            try:
                decoded = raw_name.decode(encoding, errors="strict")
            except UnicodeDecodeError:
                score -= 12
                continue
            decoded_count += 1
            name_score, stats = self._score_decoded_name(decoded, encoding)
            score += name_score
            total_cjk += stats["cjk"]
            total_kana += stats["kana"]
            total_halfwidth_kana += stats["halfwidth_kana"]
            total_latin_symbols += stats["latin_symbols"]

        if decoded_count == len(raw_names):
            score += 4
        if total_cjk:
            reasons.append(f"识别到 CJK 字符 {total_cjk} 个")
        if total_kana:
            reasons.append(f"识别到日文假名 {total_kana} 个")
        if total_halfwidth_kana:
            reasons.append(f"识别到半角假名 {total_halfwidth_kana} 个")
        if total_latin_symbols:
            reasons.append(f"疑似西文符号噪声 {total_latin_symbols} 个")
        return score, decoded_count, reasons

    def _score_decoded_name(self, decoded: str, encoding: str) -> Tuple[int, Dict[str, int]]:
        score = 0
        stats = {"cjk": 0, "kana": 0, "halfwidth_kana": 0, "latin_symbols": 0}
        if not decoded:
            return -5, stats

        if "\x00" in decoded or any(ord(ch) < 32 for ch in decoded if ch not in "\t\n\r"):
            score -= 20
        if re.search(r'[<>:"|?*]', decoded):
            score -= 10
        if any(part in {"", ".", ".."} for part in re.split(r"[\\/]+", decoded) if part != ""):
            score -= 3

        ascii_chars = sum(1 for ch in decoded if ord(ch) < 128)
        cjk_chars = sum(1 for ch in decoded if "\u4e00" <= ch <= "\u9fff")
        kana_chars = sum(1 for ch in decoded if "\u3040" <= ch <= "\u30ff")
        halfwidth_kana_chars = sum(1 for ch in decoded if "\uff66" <= ch <= "\uff9f")
        latin_symbols = sum(1 for ch in decoded if "\u00a0" <= ch <= "\u00ff" or "\u2500" <= ch <= "\u259f")
        stats["cjk"] = cjk_chars
        stats["kana"] = kana_chars
        stats["halfwidth_kana"] = halfwidth_kana_chars
        stats["latin_symbols"] = latin_symbols

        score += min(ascii_chars, 16) // 4
        if encoding == "cp932":
            score += kana_chars * 5 + halfwidth_kana_chars + cjk_chars
            score += sum(1 for ch in decoded if ch in self.JAPANESE_COMMON_KANJI) * 4
            if halfwidth_kana_chars and not kana_chars:
                score -= halfwidth_kana_chars * 3
        elif encoding == "cp936":
            score += cjk_chars * 3
            score -= (kana_chars + halfwidth_kana_chars) * 2
            score += sum(1 for ch in decoded if ch in self.SIMPLIFIED_COMMON_CHARS) * 2
            score -= sum(1 for ch in decoded if ch in self.TRADITIONAL_COMMON_CHARS - self.SIMPLIFIED_COMMON_CHARS)
            score -= sum(1 for ch in decoded if ch in self.JAPANESE_COMMON_KANJI - self.SIMPLIFIED_COMMON_CHARS)
        elif encoding == "cp950":
            score += cjk_chars * 3
            score -= (kana_chars + halfwidth_kana_chars) * 2
            score += sum(1 for ch in decoded if ch in self.TRADITIONAL_COMMON_CHARS) * 2
            score -= sum(1 for ch in decoded if ch in self.SIMPLIFIED_COMMON_CHARS - self.TRADITIONAL_COMMON_CHARS)
        elif encoding == "utf-8":
            score += (cjk_chars + kana_chars) * 4
        elif encoding == "cp437":
            score -= latin_symbols * 2

        score -= latin_symbols
        return score, stats

    def _is_ascii_name(self, raw_name: bytes) -> bool:
        return all(byte < 128 for byte in raw_name)
