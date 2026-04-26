import itertools
import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import List, Optional

from smart_unpacker.support.sevenzip_native import get_native_password_tester
from smart_unpacker.relations.internal.group_builder import RelationsGroupBuilder


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

    def _collect_misnamed_volume_candidates(self, archive: str, all_parts: List[str], archive_prefix: str, style: str):
        return self._relations.collect_misnamed_volume_candidates(archive, all_parts, archive_prefix, style)

    def _link_or_copy(self, source: str, target: str):
        try:
            os.link(source, target)
        except OSError:
            shutil.copy2(source, target)

    def normalize(self, archive: str, all_parts: List[str], startupinfo=None) -> StagedSplit:
        confirmed_parts = list(dict.fromkeys(all_parts))
        parsed_main = self._relations.parse_numbered_volume(os.path.normpath(archive))
        if not parsed_main or parsed_main["number"] != 1:
            return StagedSplit(archive=archive, run_parts=confirmed_parts, cleanup_parts=confirmed_parts)

        archive_prefix = parsed_main["prefix"]
        style = parsed_main["style"]
        width = parsed_main["width"]
        numbered_parts = {}
        for path in all_parts:
            parsed = self._relations.parse_numbered_volume(os.path.normpath(path))
            if parsed and parsed["style"] == style and os.path.normcase(parsed["prefix"]) == os.path.normcase(archive_prefix):
                numbered_parts[parsed["number"]] = os.path.normpath(path)

        candidates = self._collect_misnamed_volume_candidates(archive, all_parts, archive_prefix, style)
        if not candidates:
            return StagedSplit(archive=archive, run_parts=confirmed_parts, cleanup_parts=confirmed_parts)

        total_count = len(numbered_parts) + len(candidates)
        missing_numbers = [number for number in range(1, total_count + 1) if number not in numbered_parts]
        if len(missing_numbers) != len(candidates):
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
                for number in range(1, total_count + 1)
            ]
            target_paths = [self._format_numbered_volume(staged_prefix, number, style, width) for number in missing_numbers]
            permutations = itertools.permutations(candidates)
            if len(candidates) > 7:
                permutations = ()
            for permutation in permutations:
                for target in target_paths:
                    try:
                        os.unlink(target)
                    except FileNotFoundError:
                        pass
                for source, target in zip(permutation, target_paths):
                    self._link_or_copy(source, target)

                staged_archive = self._format_numbered_volume(staged_prefix, 1, style, width)
                result = self._native_tester.test_archive(staged_archive, part_paths=staged_paths)
                if result.ok:
                    used_candidates = list(permutation)
                    cleanup_parts = list(dict.fromkeys(list(all_parts) + used_candidates))
                    print("[RENAME] Fixed misnamed split volumes in temporary staging directory.")
                    return StagedSplit(
                        archive=staged_archive,
                        run_parts=staged_paths,
                        cleanup_parts=cleanup_parts,
                        candidate_parts=used_candidates,
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
