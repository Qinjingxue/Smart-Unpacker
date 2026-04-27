import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import List, Optional

from smart_unpacker.support.sevenzip_native import get_native_password_tester
from smart_unpacker.relations.internal.group_builder import RelationsGroupBuilder
from smart_unpacker.support.path_keys import case_key, normalized_path


@dataclass
class StagedSplit:
    archive: str
    run_parts: List[str]
    cleanup_parts: List[str]
    candidate_parts: List[str] | None = None
    temp_dir: Optional[str] = None
    verified_candidates: bool = False

    @property
    def all_parts(self) -> List[str]:
        return list(self.run_parts)


class SplitVolumeNormalizer:
    """Creates a 7-Zip-friendly view of split archive groups.

    The normalizer lives in the rename layer because its job is filename/layout
    normalization, not extraction. It may return original paths for already
    standard groups, or a temporary hardlink/copy staging directory when
    misnamed members need to be presented with canonical volume names.
    """

    def __init__(self):
        self._relations = RelationsGroupBuilder()
        self._native_tester = get_native_password_tester()

    def _format_numbered_volume(self, prefix: str, number: int, style: str, width: int) -> str:
        if style == "rar_part":
            return f"{prefix}.part{number:0{width}d}.rar"
        return f"{prefix}.{number:03d}"

    def _link_or_copy(self, source: str, target: str):
        try:
            os.link(source, target)
        except OSError:
            shutil.copy2(source, target)

    def normalize(
        self,
        archive: str,
        all_parts: List[str],
        startupinfo=None,
        volume_entries: list[dict] | None = None,
    ) -> StagedSplit:
        confirmed_parts = list(dict.fromkeys(all_parts))
        entries = self._normalize_volume_entries(archive, confirmed_parts, volume_entries)
        if not entries:
            return StagedSplit(archive=archive, run_parts=confirmed_parts, cleanup_parts=confirmed_parts)

        first_entry = next((entry for entry in entries if entry["number"] == 1), None)
        if not first_entry:
            return StagedSplit(archive=archive, run_parts=confirmed_parts, cleanup_parts=confirmed_parts)

        archive_prefix = first_entry["prefix"]
        style = first_entry["style"]
        width = first_entry["width"]
        numbered_parts = {
            int(entry["number"]): normalized_path(entry["path"])
            for entry in entries
            if entry.get("source") == "standard"
        }
        candidate_entries = [entry for entry in entries if entry.get("source") != "standard"]
        candidates = [normalized_path(entry["path"]) for entry in candidate_entries]
        if not candidates:
            return StagedSplit(archive=archive, run_parts=confirmed_parts, cleanup_parts=confirmed_parts)

        candidate_numbers = [int(entry["number"]) for entry in candidate_entries]
        if len(set(candidate_numbers)) != len(candidate_numbers):
            return StagedSplit(
                archive=archive,
                run_parts=confirmed_parts,
                cleanup_parts=confirmed_parts,
                candidate_parts=list(dict.fromkeys(candidates)),
            )

        temp_dir = tempfile.mkdtemp(prefix=".smart-unpacker-volumes-", dir=os.path.dirname(archive) or None)
        try:
            staged_prefix = os.path.join(temp_dir, os.path.basename(archive_prefix))
            for number, source in numbered_parts.items():
                self._link_or_copy(source, self._format_numbered_volume(staged_prefix, number, style, width))

            staged_paths = [
                self._format_numbered_volume(staged_prefix, number, style, width)
                for number in sorted({int(entry["number"]) for entry in entries})
            ]
            for entry in candidate_entries:
                target = self._format_numbered_volume(staged_prefix, int(entry["number"]), style, width)
                try:
                    os.unlink(target)
                except FileNotFoundError:
                    pass
                self._link_or_copy(normalized_path(entry["path"]), target)

            staged_archive = self._format_numbered_volume(staged_prefix, 1, style, width)
            result = self._native_tester.test_archive(staged_archive, part_paths=staged_paths)
            if result.ok:
                cleanup_parts = list(dict.fromkeys(list(all_parts) + candidates))
                print("[RENAME] Fixed misnamed split volumes in temporary staging directory.")
                return StagedSplit(
                    archive=staged_archive,
                    run_parts=staged_paths,
                    cleanup_parts=cleanup_parts,
                    candidate_parts=candidates,
                    temp_dir=temp_dir,
                    verified_candidates=True,
                )
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

        shutil.rmtree(temp_dir, ignore_errors=True)
        return StagedSplit(
            archive=archive,
            run_parts=confirmed_parts,
            cleanup_parts=confirmed_parts,
            candidate_parts=list(dict.fromkeys(candidates)),
        )

    def cleanup(self, staged: StagedSplit):
        if staged.temp_dir:
            shutil.rmtree(staged.temp_dir, ignore_errors=True)

    def _normalize_volume_entries(
        self,
        archive: str,
        all_parts: list[str],
        volume_entries: list[dict] | None,
    ) -> list[dict]:
        if volume_entries:
            normalized = []
            for entry in volume_entries:
                if not isinstance(entry, dict) or not entry.get("path") or not entry.get("number"):
                    continue
                normalized.append({
                    "path": normalized_path(str(entry["path"])),
                    "number": int(entry["number"]),
                    "source": str(entry.get("source") or "standard"),
                    "style": str(entry.get("style") or ""),
                    "prefix": str(entry.get("prefix") or ""),
                    "width": int(entry.get("width") or 3),
                })
            return normalized

        parsed_main = self._relations.parse_numbered_volume(normalized_path(archive))
        if not parsed_main or parsed_main["number"] != 1:
            return []

        archive_prefix = str(parsed_main["prefix"])
        style = str(parsed_main["style"])
        width = int(parsed_main["width"])
        normalized = []
        for path in all_parts:
            parsed = self._relations.parse_numbered_volume(normalized_path(path))
            if parsed and parsed["style"] == style and case_key(parsed["prefix"]) == case_key(archive_prefix):
                normalized.append({
                    "path": normalized_path(path),
                    "number": int(parsed["number"]),
                    "source": "standard",
                    "style": style,
                    "prefix": archive_prefix,
                    "width": width,
                })
        return normalized
