import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

from packrelic_native import (
    list_regular_files_in_directory as _native_list_regular_files_in_directory,
    relations_build_candidate_groups as _native_build_candidate_groups,
    relations_detect_split_role as _native_detect_split_role,
    relations_logical_name as _native_logical_name,
    relations_parse_numbered_volume as _native_parse_numbered_volume,
    relations_split_sort_key as _native_split_sort_key,
)

from packrelic.contracts.filesystem import DirectorySnapshot, FileEntry
from packrelic.relations.internal.models import CandidateGroup, DirectoryFileIndex, FileRelation, SplitVolumeEntry
from packrelic.support.path_keys import case_key, normalized_path, path_key


class RelationsGroupBuilder:
    FUZZY_TIME_WINDOW_NS = 24 * 60 * 60 * 1_000_000_000

    def build_candidate_groups(self, snapshot: DirectorySnapshot) -> List[CandidateGroup]:
        rows = []
        dir_files: Dict[str, List[FileEntry]] = defaultdict(list)
        for entry in snapshot.entries:
            parent = str(entry.path.parent)
            if not entry.is_dir:
                dir_files[parent].append(entry)
            rows.append({
                "path": str(entry.path),
                "parent": parent,
                "name": entry.path.name,
                "is_dir": bool(entry.is_dir),
                "size": entry.size,
                "mtime_ns": entry.mtime_ns,
            })
        directory_indexes = {
            directory: self._build_directory_index(entries)
            for directory, entries in dir_files.items()
        }
        native_groups = _native_build_candidate_groups(rows)
        groups: List[CandidateGroup] = []
        for raw in native_groups:
            if not isinstance(raw, dict):
                raise ValueError("native relations returned a non-object group")
            group = self._candidate_group_from_native(raw, directory_indexes)
            if group is None:
                raise ValueError("native relations returned an invalid group")
            groups.append(group)
        return groups

    def _candidate_group_from_native(
        self,
        raw: dict,
        directory_indexes: Dict[str, DirectoryFileIndex],
    ) -> CandidateGroup | None:
        relation_payload = raw.get("relation")
        if not isinstance(relation_payload, dict):
            return None
        try:
            relation = FileRelation(**relation_payload)
            head_path = str(raw.get("head_path") or "")
            all_parts = [str(path) for path in (raw.get("all_parts") or [])]
            directory_index = directory_indexes.get(str(raw.get("directory") or ""))
            if not head_path or not all_parts:
                return None
            if bool(raw.get("expand_misnamed")):
                all_parts = self.expand_misnamed_split_parts(head_path, all_parts, directory_index)
            split_volumes, split_complete, missing_reason, missing_indices = self.build_split_volume_entries(
                head_path,
                all_parts,
                directory_index,
            )
            first_volume = next((volume for volume in split_volumes if volume.number == 1), None)
            if first_volume:
                head_path = first_volume.path
            return CandidateGroup(
                head_path=head_path,
                logical_name=str(raw.get("logical_name") or relation.logical_name),
                relation=relation,
                member_paths=[path for path in all_parts if path_key(path) != path_key(head_path)],
                is_split_candidate=bool(raw.get("is_split_candidate")),
                head_size=raw.get("head_size"),
                split_volumes=split_volumes,
                split_group_complete=split_complete,
                split_missing_reason=missing_reason,
                split_missing_indices=missing_indices,
            )
        except (TypeError, ValueError):
            return None

    def _build_directory_index(self, entries: List[FileEntry]) -> DirectoryFileIndex:
        lower_names = {entry.path.name.lower() for entry in entries}
        by_norm_path = {
            path_key(entry.path): entry
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
        return _native_detect_split_role(filename)

    def get_logical_name(self, filename: str, is_archive: bool = False) -> str:
        return _native_logical_name(filename, is_archive)

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
        return _native_parse_numbered_volume(path)

    def select_first_volume(self, paths: List[str]) -> str:
        if not paths:
            return ""

        for path in paths:
            parsed = self.parse_numbered_volume(normalized_path(path))
            if parsed and parsed["number"] == 1:
                return path

        lower_names = {os.path.basename(path).lower() for path in paths}
        for path in paths:
            if self.is_oldstyle_rar_head(path, lower_names):
                return path

        return ""

    def should_scan_split_siblings(self, archive: str, is_split: bool = False, is_sfx_stub: bool = False) -> bool:
        if is_split or is_sfx_stub:
            return True
        parsed = self.parse_numbered_volume(normalized_path(archive))
        if parsed and parsed["number"] == 1:
            return True
        return os.path.splitext(archive)[1].lower() in {".exe", ".rar"}

    def find_standard_split_siblings(self, archive: str) -> List[str]:
        directory = os.path.dirname(archive) or "."
        archive_name = os.path.basename(archive)
        parsed_archive = self.parse_numbered_volume(archive_name)
        if parsed_archive and parsed_archive["style"] == "rar_part":
            base = str(parsed_archive["prefix"])
        else:
            base = os.path.splitext(archive_name)[0]
        entries = self._iter_directory_files(directory)
        names = [entry.path.name for entry in entries]

        lower_names = {name.lower() for name in names}
        expected_heads = {
            f"{base}.7z.001".lower(),
            f"{base}.zip.001".lower(),
            f"{base}.rar.001".lower(),
            f"{base}.001".lower(),
            f"{base}.part1.rar".lower(),
            f"{base}.part01.rar".lower(),
            f"{base}.part001.rar".lower(),
            f"{base}.part1.exe".lower(),
            f"{base}.part01.exe".lower(),
            f"{base}.part001.exe".lower(),
        }
        oldstyle_rar_head = f"{base}.rar".lower()
        oldstyle_rar_present = oldstyle_rar_head in lower_names and any(
            f"{base}.r{number:02d}".lower() in lower_names for number in range(0, 100)
        )
        if oldstyle_rar_present:
            expected_heads.add(f"{base}.rar".lower())

        if not (expected_heads & lower_names):
            return []

        siblings = []
        for entry in entries:
            name = entry.path.name
            lower = name.lower()
            if self.is_standard_split_sibling(base.lower(), lower, oldstyle_rar_present):
                siblings.append(os.path.join(directory, name))

        return sorted(siblings, key=self.split_sort_key)

    def is_standard_split_sibling(self, base: str, lower_name: str, oldstyle_rar_present: bool) -> bool:
        if re.match(rf"^{re.escape(base)}\.(7z|zip|rar)\.\d{{3}}$", lower_name):
            return True
        if re.match(rf"^{re.escape(base)}\.\d{{3}}$", lower_name):
            return True
        if re.match(rf"^{re.escape(base)}\.part\d+\.(rar|exe)$", lower_name):
            return True
        if oldstyle_rar_present and lower_name == f"{base}.rar":
            return True
        if oldstyle_rar_present and re.match(rf"^{re.escape(base)}\.r\d{{2}}$", lower_name):
            return True
        return False

    def split_sort_key(self, path: str) -> tuple[int, int, str]:
        raw = _native_split_sort_key(normalized_path(path))
        return (int(raw[0]), int(raw[1]), str(raw[2]))

    def is_oldstyle_rar_head(self, path: str, lower_names: Set[str]) -> bool:
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
        known = {path_key(path) for path in all_parts}
        candidates = []

        for path in all_parts:
            norm_path = normalized_path(path)
            if self.parse_numbered_volume(norm_path):
                continue
            if self._looks_like_misnamed_volume(norm_path, archive_prefix, logical_base, style):
                candidates.append(norm_path)

        for entry in self._iter_misnamed_volume_files(directory, archive_prefix, logical_base, style, directory_index):
            path = normalized_path(entry.path)
            norm_key = path_key(path)
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
                key = path_key(entry.path)
                if key not in seen:
                    seen.add(key)
                    candidates.append(entry)

        if style == "rar_part":
            for entry in directory_index.entries:
                name = entry.path.name.lower()
                if logical_name not in name or ".part" not in name or ".rar." not in name:
                    continue
                key = path_key(entry.path)
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
        parsed_main = self.parse_numbered_volume(normalized_path(archive))
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

    def build_split_volume_entries(
        self,
        archive: str,
        all_parts: List[str],
        directory_index: DirectoryFileIndex | None = None,
    ) -> tuple[List[SplitVolumeEntry], bool | None, str, List[int]]:
        parsed_main = self.parse_numbered_volume(normalized_path(archive))
        if not parsed_main:
            if os.path.splitext(archive)[1].lower() == ".exe":
                return [], None, "", []
            parsed_main = self._first_parsed_volume(all_parts)
        if not parsed_main:
            return [], None, "", []

        archive_prefix = str(parsed_main["prefix"])
        style = str(parsed_main["style"])
        width = int(parsed_main["width"])
        confirmed: dict[int, str] = {}
        candidates: List[str] = []
        seen_paths: set[str] = set()

        for path in all_parts:
            norm_path = normalized_path(path)
            path_id = path_key(norm_path)
            if path_id in seen_paths:
                continue
            seen_paths.add(path_id)

            parsed = self.parse_numbered_volume(norm_path)
            if parsed and parsed["style"] == style and case_key(parsed["prefix"]) == case_key(archive_prefix):
                confirmed[int(parsed["number"])] = norm_path
            else:
                candidates.append(norm_path)

        if not confirmed:
            return [], None, "", []

        max_confirmed = max(confirmed)
        missing_numbers = [number for number in range(1, max_confirmed + 1) if number not in confirmed]
        fuzzy_candidates = self._find_fuzzy_candidates_for_missing_volumes(
            archive=archive,
            archive_prefix=archive_prefix,
            style=style,
            known_paths=set(seen_paths),
            directory_index=directory_index,
        )

        assigned_candidates: dict[int, str] = {}
        available_candidates = list(dict.fromkeys(candidates + fuzzy_candidates))
        for number in missing_numbers:
            match = self._select_candidate_for_missing_number(
                number,
                available_candidates,
                archive_prefix,
                style,
            )
            if not match:
                continue
            assigned_candidates[number] = match
            available_candidates = [path for path in available_candidates if path_key(path) != path_key(match)]

        next_number = max_confirmed + 1
        for path in available_candidates:
            while next_number in confirmed or next_number in assigned_candidates:
                next_number += 1
            assigned_candidates[next_number] = path
            next_number += 1

        entries: List[SplitVolumeEntry] = [
            SplitVolumeEntry(
                path=path,
                number=number,
                role="first" if number == 1 else "member",
                source="standard",
                style=style,
                prefix=archive_prefix,
                width=width,
            )
            for number, path in sorted(confirmed.items())
        ]

        for number, path in sorted(assigned_candidates.items()):
            entries.append(SplitVolumeEntry(
                path=path,
                number=number,
                role="first" if number == 1 else "member",
                source="candidate",
                style=style,
                prefix=archive_prefix,
                width=width,
            ))

        unresolved = [number for number in missing_numbers if number not in assigned_candidates]
        if unresolved:
            reason = "missing_head" if 1 in unresolved else "missing_middle"
            return sorted(entries, key=lambda volume: (volume.number, volume.path.lower())), False, reason, unresolved

        return sorted(entries, key=lambda volume: (volume.number, volume.path.lower())), True, "", []

    def _first_parsed_volume(self, all_parts: List[str]):
        parsed_items = []
        for path in all_parts:
            parsed = self.parse_numbered_volume(normalized_path(path))
            if parsed:
                parsed_items.append(parsed)
        if not parsed_items:
            return None
        return sorted(parsed_items, key=lambda item: int(item["number"]))[0]

    def _find_fuzzy_candidates_for_missing_volumes(
        self,
        archive: str,
        archive_prefix: str,
        style: str,
        known_paths: set[str],
        directory_index: DirectoryFileIndex | None,
    ) -> List[str]:
        reference_path = self._reference_path_for_prefix(archive, archive_prefix, style, directory_index)
        if not reference_path:
            return []
        return self._collect_fuzzy_volume_candidates(
            reference_path,
            archive_prefix,
            style,
            set(known_paths),
            directory_index=directory_index,
        )

    def _reference_path_for_prefix(
        self,
        archive: str,
        archive_prefix: str,
        style: str,
        directory_index: DirectoryFileIndex | None,
    ) -> str:
        parsed_archive = self.parse_numbered_volume(normalized_path(archive))
        if parsed_archive and parsed_archive["style"] == style and case_key(parsed_archive["prefix"]) == case_key(archive_prefix):
            return normalized_path(archive)
        entries = self._iter_directory_files(os.path.dirname(archive), directory_index)
        candidates = []
        for entry in entries:
            parsed = self.parse_numbered_volume(normalized_path(entry.path))
            if parsed and parsed["style"] == style and case_key(parsed["prefix"]) == case_key(archive_prefix):
                candidates.append((int(parsed["number"]), normalized_path(entry.path)))
        return sorted(candidates)[0][1] if candidates else ""

    def _select_candidate_for_missing_number(
        self,
        number: int,
        candidates: List[str],
        archive_prefix: str,
        style: str,
    ) -> str:
        if not candidates:
            return ""
        archive_name = os.path.basename(archive_prefix).lower()
        logical_name = os.path.splitext(archive_name)[0] if style != "rar_part" else archive_name
        exact_names = set()
        if number == 1:
            exact_names.update({archive_name, logical_name})
            if style == "rar_part":
                exact_names.add(f"{logical_name}.rar")
        exact_names.add(f"{archive_name}.{number}")
        exact_names.add(f"{archive_name}.{number:02d}")
        if style == "rar_part":
            exact_names.add(f"{logical_name}.rar.{number}")
            exact_names.add(f"{logical_name}.rar.{number:02d}")

        for path in sorted(candidates, key=lambda item: os.path.basename(item).lower()):
            if os.path.basename(path).lower() in exact_names:
                return path
        return sorted(candidates, key=lambda item: os.path.basename(item).lower())[0]

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
            split_volumes, split_complete, missing_reason, missing_indices = self.build_split_volume_entries(
                str(entry.path),
                all_parts,
                directory_index,
            )
            head_path = str(entry.path)
            first_volume = next((volume for volume in split_volumes if volume.number == 1), None)
            if first_volume:
                head_path = first_volume.path
            return CandidateGroup(
                head_path=head_path,
                logical_name=relation.logical_name,
                relation=relation,
                member_paths=[path for path in all_parts if path_key(path) != path_key(head_path)],
                is_split_candidate=relation.is_split_related,
                head_size=entry.size,
                split_volumes=split_volumes,
                split_group_complete=split_complete,
                split_missing_reason=missing_reason,
                split_missing_indices=missing_indices,
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

        split_volumes, split_complete, missing_reason, missing_indices = self.build_split_volume_entries(
            str(head_entry.path),
            all_parts,
            directory_index,
        )
        head_path = str(head_entry.path)
        first_volume = next((volume for volume in split_volumes if volume.number == 1), None)
        if first_volume:
            head_path = first_volume.path

        return CandidateGroup(
            head_path=head_path,
            logical_name=relation.logical_name,
            relation=relation,
            member_paths=[path for path in all_parts if path_key(path) != path_key(head_path)],
            is_split_candidate=True,
            head_size=head_entry.size,
            split_volumes=split_volumes,
            split_group_complete=split_complete,
            split_missing_reason=missing_reason,
            split_missing_indices=missing_indices,
        )

    def _has_split_companions_in_dir(self, sibling_names: Set[str], base_name: str) -> bool:
        patterns = [
            re.compile(re.escape(base_name) + r"\.(7z|zip|rar)\.\d+(?:\.[^.]+)?$", re.IGNORECASE),
            re.compile(re.escape(base_name) + r"\.\d{3}(?:\.[^.]+)?$", re.IGNORECASE),
            re.compile(re.escape(base_name) + r"\.part\d+\.(?:rar|exe)(?:\.[^.]+)?$", re.IGNORECASE),
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

        rows = _native_list_regular_files_in_directory(directory)
        entries: List[FileEntry] = []
        for row in rows:
            if not isinstance(row, dict) or not row.get("path"):
                continue
            entries.append(
                FileEntry(
                    path=Path(row["path"]),
                    is_dir=False,
                    size=row.get("size"),
                    mtime_ns=row.get("mtime_ns"),
                )
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
        archive_key = path_key(archive)
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
            path = normalized_path(entry.path)
            norm_key = path_key(path)
            if norm_key in known:
                continue

            parsed = self.parse_numbered_volume(path)
            if parsed and parsed["style"] == style and case_key(parsed["prefix"]) == case_key(archive_prefix):
                continue

            if entry.size is None or entry.mtime_ns is None:
                continue
            if entry.size < min_size or entry.size > main_size:
                continue
            if abs(entry.mtime_ns - archive_mtime_ns) > self.FUZZY_TIME_WINDOW_NS:
                continue
            if not self._looks_like_fuzzy_volume_candidate(path, archive_prefix, style):
                continue
            fuzzy.append(path)
            known.add(norm_key)
        return fuzzy
