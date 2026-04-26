import os
import re
import stat as stat_module
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

from smart_unpacker.contracts.filesystem import DirectorySnapshot, FileEntry
from smart_unpacker.relations.internal.models import CandidateGroup, DirectoryFileIndex, FileRelation


SPLIT_FIRST_PATTERNS = [
    re.compile(r"\.part0*1\.rar(?:\.[^.]+)?$", re.IGNORECASE),
    re.compile(r"\.(7z|zip|rar)\.001(?:\.[^.]+)?$", re.IGNORECASE),
    re.compile(r"\.001(?:\.[^.]+)?$", re.IGNORECASE),
]

SPLIT_MEMBER_PATTERN = re.compile(r"\.(part\d+\.rar|\d{3})(?:\.[^.]+)?$", re.IGNORECASE)


class RelationsGroupBuilder:
    def build_candidate_groups(self, snapshot: DirectorySnapshot) -> List[CandidateGroup]:
        dir_files: Dict[str, List[FileEntry]] = defaultdict(list)
        for entry in snapshot.entries:
            if not entry.is_dir:
                parent = str(entry.path.parent)
                dir_files[parent].append(entry)

        groups: List[CandidateGroup] = []

        for _, entries in dir_files.items():
            directory_index = self._build_directory_index(entries)
            relations = {
                entry.path.name: self._build_file_relation(entry.path.name, directory_index.lower_names)
                for entry in entries
            }

            logical_groups: Dict[str, List[FileEntry]] = defaultdict(list)
            for entry in entries:
                logical_groups[relations[entry.path.name].logical_name].append(entry)

            for _, group_entries in logical_groups.items():
                if not group_entries:
                    continue

                if any(relations[entry.path.name].is_split_related for entry in group_entries):
                    group_entries = [
                        entry for entry in group_entries
                        if relations[entry.path.name].is_split_related
                    ]
                    if not group_entries:
                        continue

                groups.append(self._build_group(group_entries, relations, directory_index))

        return groups

    def _build_directory_index(self, entries: List[FileEntry]) -> DirectoryFileIndex:
        lower_names = {entry.path.name.lower() for entry in entries}
        by_norm_path = {
            os.path.normcase(os.path.normpath(str(entry.path))): entry
            for entry in entries
        }
        by_lower_name: Dict[str, List[FileEntry]] = defaultdict(list)
        for entry in entries:
            by_lower_name[entry.path.name.lower()].append(entry)
        return DirectoryFileIndex(
            entries=entries,
            lower_names=lower_names,
            by_norm_path=by_norm_path,
            by_lower_name=dict(by_lower_name),
        )

    def detect_split_role(self, filename: str) -> Optional[str]:
        if any(pattern.search(filename) for pattern in SPLIT_FIRST_PATTERNS):
            return "first"
        if SPLIT_MEMBER_PATTERN.search(filename):
            return "member"
        return None

    def get_logical_name(self, filename: str, is_archive: bool = False) -> str:
        name, count = re.subn(r"\.part\d+\.rar(?:\.[^.]+)?$", "", filename, flags=re.IGNORECASE)
        if count > 0:
            return name.strip().rstrip(".")

        name, count = re.subn(r"\.(7z|zip|rar)\.\d{3}(?:\.[^.]+)?$", "", name, flags=re.IGNORECASE)
        if count > 0:
            return name.strip().rstrip(".")

        name, count = re.subn(r"\.\d{3}$", "", name, flags=re.IGNORECASE)
        if count > 0:
            return name.strip().rstrip(".")

        base, ext = os.path.splitext(filename)
        if is_archive or ext.lower() in (".7z", ".rar", ".zip", ".gz", ".bz2", ".xz", ".exe"):
            return base.strip().rstrip(".")

        return filename.strip().rstrip(".")

    def build_file_relation(self, filename: str, sibling_names: Set[str]) -> FileRelation:
        return self._build_file_relation(filename, {name.lower() for name in sibling_names})

    def _build_file_relation(self, filename: str, lower_names: Set[str]) -> FileRelation:
        base, ext = os.path.splitext(filename)
        ext = ext.lower()
        split_role = self.detect_split_role(filename)
        parsed_volume = self.parse_numbered_volume(filename)
        split_family = ""
        split_index = 0
        if parsed_volume:
            split_index = int(parsed_volume["number"])
            if parsed_volume["style"] == "rar_part":
                split_family = "rar_part"
            else:
                parsed_prefix = str(parsed_volume["prefix"]).lower()
                if parsed_prefix.endswith(".7z"):
                    split_family = "7z_numbered"
                elif parsed_prefix.endswith(".zip"):
                    split_family = "zip_numbered"
                elif parsed_prefix.endswith(".rar"):
                    split_family = "rar_numbered"
                else:
                    split_family = "generic_numbered"
        logical_name = self.get_logical_name(filename)

        has_generic_001_head = f"{base}.001".lower() in lower_names
        is_plain_numeric_member = bool(re.search(r"\.\d{3}(?:\.[^.]+)?$", filename, re.IGNORECASE)) and not bool(
            re.search(r"\.(7z|zip|rar)\.\d{3}(?:\.[^.]+)?$", filename, re.IGNORECASE)
        )
        is_split_member = split_role is not None
        if split_role == "member" and is_plain_numeric_member and not has_generic_001_head:
            is_split_member = False
            split_role = None

        has_split_companions = False
        is_split_exe_companion = False
        is_disguised_split_exe_companion = False

        if ext == ".exe":
            has_split_companions = self._has_split_companions_in_dir(lower_names, base)
            is_split_exe_companion = has_split_companions
            if has_split_companions:
                logical_name = base
                split_family = "exe_companion"
                split_index = 1
        elif base.lower().endswith(".exe"):
            logical_base = base[:-4]
            has_split_companions = self._has_split_companions_in_dir(lower_names, logical_base)
            is_disguised_split_exe_companion = has_split_companions
            if has_split_companions:
                logical_name = logical_base
                split_family = "exe_companion"
                split_index = 1

        match_rar_disguised = re.search(r"^(.*\.part)0*1\.rar(?:\.[^.]+)?$", filename, re.IGNORECASE) is not None
        match_rar_head = re.search(r"^(.*\.part)0*1$", base, re.IGNORECASE) is not None
        match_001_head = re.search(r"^(.*)\.001$", base, re.IGNORECASE) is not None

        return FileRelation(
            filename=filename,
            logical_name=logical_name,
            split_role=split_role,
            is_split_member=is_split_member,
            has_generic_001_head=has_generic_001_head,
            is_plain_numeric_member=is_plain_numeric_member,
            has_split_companions=has_split_companions,
            is_split_exe_companion=is_split_exe_companion,
            is_disguised_split_exe_companion=is_disguised_split_exe_companion,
            is_split_related=is_split_member or is_split_exe_companion or is_disguised_split_exe_companion,
            match_rar_disguised=match_rar_disguised,
            match_rar_head=match_rar_head,
            match_001_head=match_001_head,
            split_family=split_family,
            split_index=split_index,
        )

    def parse_numbered_volume(self, path: str):
        match = re.search(r"^(?P<prefix>.+\.(?:7z|zip|rar))\.(?P<number>\d{3})$", path, re.IGNORECASE)
        if not match:
            match = re.search(r"^(?P<prefix>.+)\.part(?P<number>\d+)\.rar$", path, re.IGNORECASE)
            if not match:
                match = re.search(r"^(?P<prefix>.+)\.(?P<number>\d{3})$", path, re.IGNORECASE)
                if not match:
                    return None
                return {
                    "prefix": match.group("prefix"),
                    "number": int(match.group("number")),
                    "style": "plain_numeric_suffix",
                    "width": 3,
                }
            return {
                "prefix": match.group("prefix"),
                "number": int(match.group("number")),
                "style": "rar_part",
                "width": len(match.group("number")),
            }
        return {
            "prefix": match.group("prefix"),
            "number": int(match.group("number")),
            "style": "numeric_suffix",
            "width": 3,
        }

    def select_first_volume(self, paths: List[str]) -> str:
        if not paths:
            return ""

        for path in paths:
            parsed = self.parse_numbered_volume(os.path.normpath(path))
            if parsed and parsed["number"] == 1:
                return path

        lower_names = {os.path.basename(path).lower() for path in paths}
        for path in paths:
            if self.is_legacy_rar_head(path, lower_names):
                return path

        return ""

    def should_scan_split_siblings(self, archive: str, is_split: bool = False, is_sfx_stub: bool = False) -> bool:
        if is_split or is_sfx_stub:
            return True
        parsed = self.parse_numbered_volume(os.path.normpath(archive))
        if parsed and parsed["number"] == 1:
            return True
        return os.path.splitext(archive)[1].lower() in {".exe", ".rar"}

    def find_standard_split_siblings(self, archive: str) -> List[str]:
        directory = os.path.dirname(archive) or "."
        base = os.path.splitext(os.path.basename(archive))[0]
        try:
            names = os.listdir(directory)
        except OSError:
            return []

        lower_names = {name.lower() for name in names}
        expected_heads = {
            f"{base}.7z.001".lower(),
            f"{base}.zip.001".lower(),
            f"{base}.rar.001".lower(),
            f"{base}.001".lower(),
            f"{base}.part1.rar".lower(),
            f"{base}.part01.rar".lower(),
            f"{base}.part001.rar".lower(),
        }
        legacy_rar_head = f"{base}.rar".lower()
        legacy_rar_present = legacy_rar_head in lower_names and any(
            f"{base}.r{number:02d}".lower() in lower_names for number in range(0, 100)
        )
        if legacy_rar_present:
            expected_heads.add(f"{base}.rar".lower())

        if not (expected_heads & lower_names):
            return []

        siblings = []
        for name in names:
            lower = name.lower()
            if self.is_standard_split_sibling(base.lower(), lower, legacy_rar_present):
                siblings.append(os.path.join(directory, name))

        return sorted(siblings, key=self.split_sort_key)

    def is_standard_split_sibling(self, base: str, lower_name: str, legacy_rar_present: bool) -> bool:
        if re.match(rf"^{re.escape(base)}\.(7z|zip|rar)\.\d{{3}}$", lower_name):
            return True
        if re.match(rf"^{re.escape(base)}\.\d{{3}}$", lower_name):
            return True
        if re.match(rf"^{re.escape(base)}\.part\d+\.rar$", lower_name):
            return True
        if legacy_rar_present and lower_name == f"{base}.rar":
            return True
        if legacy_rar_present and re.match(rf"^{re.escape(base)}\.r\d{{2}}$", lower_name):
            return True
        return False

    def split_sort_key(self, path: str) -> tuple[int, int, str]:
        parsed = self.parse_numbered_volume(os.path.normpath(path))
        if parsed:
            return (0, parsed["number"], path.lower())

        lower_name = os.path.basename(path).lower()
        match = re.search(r"\.r(\d{2})$", lower_name)
        if match:
            return (1, int(match.group(1)) + 2, path.lower())
        if lower_name.endswith(".rar"):
            return (1, 1, path.lower())
        return (2, 0, path.lower())

    def is_legacy_rar_head(self, path: str, lower_names: Set[str]) -> bool:
        lower_name = os.path.basename(path).lower()
        if not lower_name.endswith(".rar"):
            return False
        base = lower_name[:-4]
        return any(f"{base}.r{number:02d}" in lower_names for number in range(0, 100))

    def collect_misnamed_volume_candidates(
        self,
        archive: str,
        all_parts: List[str],
        archive_prefix: str,
        style: str,
        directory_index: DirectoryFileIndex | None = None,
    ):
        directory = os.path.dirname(archive)
        logical_base = archive_prefix if style == "rar_part" else os.path.splitext(archive_prefix)[0]
        known = {os.path.normcase(os.path.normpath(path)) for path in all_parts}
        candidates = []

        for path in all_parts:
            norm_path = os.path.normpath(path)
            if self.parse_numbered_volume(norm_path):
                continue
            if self._looks_like_misnamed_volume(norm_path, archive_prefix, logical_base, style):
                candidates.append(norm_path)

        for entry in self._iter_misnamed_volume_files(directory, archive_prefix, logical_base, style, directory_index):
            path = os.path.normpath(str(entry.path))
            norm_key = os.path.normcase(os.path.normpath(path))
            if norm_key in known:
                continue
            if self._looks_like_misnamed_volume(path, archive_prefix, logical_base, style):
                candidates.append(path)
                known.add(norm_key)

        fuzzy_candidates = self._collect_fuzzy_volume_candidates(
            archive,
            archive_prefix,
            style,
            known,
            directory_index=directory_index,
        )
        ordered = (
            sorted(dict.fromkeys(candidates), key=lambda item: os.path.basename(item).lower())
            + sorted(dict.fromkeys(fuzzy_candidates), key=lambda item: os.path.basename(item).lower())
        )
        return list(dict.fromkeys(ordered))

    def _iter_misnamed_volume_files(
        self,
        directory: str,
        archive_prefix: str,
        logical_base: str,
        style: str,
        directory_index: DirectoryFileIndex | None,
    ) -> List[FileEntry]:
        if directory_index is None:
            return self._iter_directory_files(directory)

        archive_name = os.path.basename(archive_prefix).lower()
        logical_name = os.path.basename(logical_base).lower()
        candidate_names = {archive_name, logical_name}
        if style == "rar_part":
            candidate_names.add(f"{logical_name}.rar")
            for number in range(100):
                candidate_names.add(f"{logical_name}.rar.{number}")
                candidate_names.add(f"{logical_name}.rar.{number:02d}")
        else:
            for number in range(100):
                candidate_names.add(f"{archive_name}.{number}")
                candidate_names.add(f"{archive_name}.{number:02d}")

        seen: set[str] = set()
        candidates: List[FileEntry] = []
        for name in candidate_names:
            for entry in directory_index.by_lower_name.get(name, []):
                key = os.path.normcase(os.path.normpath(str(entry.path)))
                if key not in seen:
                    seen.add(key)
                    candidates.append(entry)

        if style == "rar_part":
            for entry in directory_index.entries:
                name = entry.path.name.lower()
                if logical_name not in name or ".part" not in name or ".rar." not in name:
                    continue
                key = os.path.normcase(os.path.normpath(str(entry.path)))
                if key not in seen:
                    seen.add(key)
                    candidates.append(entry)
        return candidates

    def expand_misnamed_split_parts(
        self,
        archive: str,
        all_parts: List[str],
        directory_index: DirectoryFileIndex | None = None,
    ) -> List[str]:
        parsed_main = self.parse_numbered_volume(os.path.normpath(archive))
        if not parsed_main or parsed_main["number"] != 1:
            return list(all_parts)
        archive_prefix = parsed_main["prefix"]
        candidates = self.collect_misnamed_volume_candidates(
            archive,
            all_parts,
            archive_prefix,
            parsed_main["style"],
            directory_index=directory_index,
        )
        return list(dict.fromkeys(list(all_parts) + candidates))

    def _build_group(
        self,
        group_entries: List[FileEntry],
        relations: Dict[str, FileRelation],
        directory_index: DirectoryFileIndex | None = None,
    ) -> CandidateGroup:
        if len(group_entries) == 1:
            entry = group_entries[0]
            relation = relations[entry.path.name]
            all_parts = [str(entry.path)]
            if self.detect_split_role(entry.path.name) == "first":
                all_parts = self.expand_misnamed_split_parts(str(entry.path), all_parts, directory_index)
            return CandidateGroup(
                head_path=str(entry.path),
                logical_name=relation.logical_name,
                relation=relation,
                member_paths=[path for path in all_parts if path != str(entry.path)],
                is_split_candidate=relation.is_split_related,
                head_size=entry.size,
            )

        head_entry = None
        for entry in group_entries:
            if entry.path.name.lower().endswith(".exe"):
                head_entry = entry
                break

        if not head_entry:
            for entry in group_entries:
                if self.detect_split_role(entry.path.name) == "first":
                    head_entry = entry
                    break

        if not head_entry:
            head_entry = sorted(group_entries, key=lambda item: item.path.name)[0]

        members = [str(entry.path) for entry in group_entries if entry != head_entry]
        all_parts = self.expand_misnamed_split_parts(
            str(head_entry.path),
            [str(head_entry.path)] + members,
            directory_index,
        )
        relation = relations[head_entry.path.name]
        split_role = relation.split_role
        if self.detect_split_role(head_entry.path.name) == "first" or head_entry.path.name.lower().endswith(".exe"):
            split_role = "first"
            relation = FileRelation(**{**relation.__dict__, "split_role": split_role})

        return CandidateGroup(
            head_path=str(head_entry.path),
            logical_name=relation.logical_name,
            relation=relation,
            member_paths=[path for path in all_parts if path != str(head_entry.path)],
            is_split_candidate=True,
            head_size=head_entry.size,
        )

    def _has_split_companions_in_dir(self, sibling_names: Set[str], base_name: str) -> bool:
        patterns = [
            re.compile(re.escape(base_name) + r"\.(7z|zip|rar)\.\d+(?:\.[^.]+)?$", re.IGNORECASE),
            re.compile(re.escape(base_name) + r"\.\d{3}(?:\.[^.]+)?$", re.IGNORECASE),
            re.compile(re.escape(base_name) + r"\.part\d+\.rar(?:\.[^.]+)?$", re.IGNORECASE),
        ]
        return any(any(pattern.match(candidate) for pattern in patterns) for candidate in sibling_names)

    def _looks_like_misnamed_volume(self, path: str, archive_prefix: str, logical_base: str, style: str) -> bool:
        name = os.path.basename(path).lower()
        archive_name = os.path.basename(archive_prefix).lower()
        logical_name = os.path.basename(logical_base).lower()
        if name == archive_name or name == logical_name:
            return True
        if style == "rar_part":
            return (
                name == f"{logical_name}.rar"
                or re.match(rf"^{re.escape(logical_name)}\.rar\.\d{{1,2}}$", name, re.IGNORECASE) is not None
                or re.match(rf"^{re.escape(logical_name)}\.part\d+\.rar\.[^.]+$", name, re.IGNORECASE) is not None
            )
        return re.match(rf"^{re.escape(archive_name)}\.\d{{1,2}}$", name, re.IGNORECASE) is not None

    def _looks_like_fuzzy_volume_candidate(self, path: str, archive_prefix: str, style: str) -> bool:
        name = os.path.basename(path).lower()
        archive_name = os.path.basename(archive_prefix).lower()
        logical_name = os.path.splitext(archive_name)[0] if style != "rar_part" else archive_name
        if name == archive_name or name == logical_name:
            return True
        if re.search(r"\.\d{1,3}$", name):
            return True
        if style == "numeric_suffix" and re.search(r"\.(7z|zip|rar|\d{1,2})$", name):
            return True
        if style == "rar_part" and (".rar" in name or ".part" in name):
            return True
        return False

    def _iter_directory_files(
        self,
        directory: str,
        directory_index: DirectoryFileIndex | None = None,
    ) -> List[FileEntry]:
        if directory_index is not None:
            return list(directory_index.entries)

        try:
            filenames = os.listdir(directory)
        except OSError:
            return []

        entries: List[FileEntry] = []
        for filename in filenames:
            path = os.path.normpath(os.path.join(directory, filename))
            try:
                stat = os.stat(path)
            except OSError:
                continue
            if not stat_module.S_ISREG(stat.st_mode):
                continue
            entries.append(
                FileEntry(path=Path(path), is_dir=False, size=stat.st_size, mtime_ns=stat.st_mtime_ns)
            )
        return entries

    def _collect_fuzzy_volume_candidates(
        self,
        archive: str,
        archive_prefix: str,
        style: str,
        known: set[str],
        directory_index: DirectoryFileIndex | None = None,
    ):
        directory = os.path.dirname(archive)
        archive_key = os.path.normcase(os.path.normpath(archive))
        archive_entry = directory_index.by_norm_path.get(archive_key) if directory_index is not None else None
        if archive_entry is not None and archive_entry.size is not None and archive_entry.mtime_ns is not None:
            main_size = max(archive_entry.size, 1)
            archive_mtime_ns = archive_entry.mtime_ns
        else:
            try:
                archive_stat = os.stat(archive)
            except OSError:
                return []
            main_size = max(archive_stat.st_size, 1)
            archive_mtime_ns = archive_stat.st_mtime_ns

        entries = self._iter_directory_files(directory, directory_index)
        if not entries:
            return []

        fuzzy = []
        min_size = max(1024 * 1024, main_size // 16)
        if min_size > main_size:
            return []
        for entry in entries:
            path = os.path.normpath(str(entry.path))
            norm_key = os.path.normcase(os.path.normpath(path))
            if norm_key in known:
                continue

            parsed = self.parse_numbered_volume(path)
            if parsed and parsed["style"] == style and os.path.normcase(parsed["prefix"]) == os.path.normcase(archive_prefix):
                continue

            if entry.size is None or entry.mtime_ns is None:
                continue
            if entry.size < min_size or entry.size > main_size:
                continue
            if abs(entry.mtime_ns - archive_mtime_ns) > 24 * 60 * 60 * 1_000_000_000:
                continue
            if not self._looks_like_fuzzy_volume_candidate(path, archive_prefix, style):
                continue
            fuzzy.append(path)
            known.add(norm_key)
        return fuzzy
