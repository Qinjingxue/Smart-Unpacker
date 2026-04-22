from __future__ import annotations

import os
import re

from smart_unpacker.support.types import FileRelation


class RelationBuilder:
    def __init__(self, engine):
        self.engine = engine

    def _make_path_info(self, root, filename):
        path = os.path.normpath(os.path.join(root, filename))
        base, ext = os.path.splitext(filename)
        return {
            "root": root,
            "filename": filename,
            "path": path,
            "base": base,
            "ext": ext.lower(),
        }

    def _normalize_relpath(self, rel_path):
        if rel_path is None:
            return ""
        return rel_path.replace("\\", "/").strip("./")

    def detect_filename_split_role(self, filename):
        if any(pattern.search(filename) for pattern in self.engine.SPLIT_FIRST_PATTERNS):
            return "first"
        if self.engine.SPLIT_MEMBER_PATTERN.search(filename):
            return "member"
        return None

    def has_split_companions_in_dir(self, filenames, logical_base):
        patterns = (
            re.compile(re.escape(logical_base) + r"\.(7z|zip|rar)\.\d+(?:\.[^.]+)?$", re.I),
            re.compile(re.escape(logical_base) + r"\.\d{3}(?:\.[^.]+)?$", re.I),
            re.compile(re.escape(logical_base) + r"\.part\d+\.rar(?:\.[^.]+)?$", re.I),
        )
        return any(any(pattern.match(candidate) for pattern in patterns) for candidate in filenames)

    def get_logical_name(self, filename: str, is_archive: bool = False) -> str:
        name, count = re.subn(r"\.part\d+\.rar(?:\.[^.]+)?$", "", filename, flags=re.I)
        if count > 0:
            return name.strip().rstrip(".")

        name, count = re.subn(r"\.(7z|zip|rar)\.\d+$", "", name, flags=re.I)
        if count > 0:
            return name.strip().rstrip(".")

        name, count = re.subn(r"\.\d{3}$", "", name, flags=re.I)
        if count > 0:
            return name.strip().rstrip(".")

        base, ext = os.path.splitext(filename)
        if is_archive or ext.lower() in (".7z", ".rar", ".zip", ".gz", ".bz2", ".xz", ".exe"):
            return base.strip().rstrip(".")

        return filename.strip().rstrip(".")

    def build_file_relation(self, root, filename, filenames, scan_root=None):
        path_info = self._make_path_info(root, filename)
        split_role = self.detect_filename_split_role(filename)
        lower_names = {name.lower() for name in filenames}
        has_generic_001_head = f"{path_info['base']}.001".lower() in lower_names
        is_plain_numeric_member = bool(re.search(r"\.\d{3}(?:\.[^.]+)?$", filename, re.I)) and not bool(
            re.search(r"\.(7z|zip|rar)\.\d{3}(?:\.[^.]+)?$", filename, re.I)
        )
        is_split_member = split_role is not None
        if split_role == "member" and is_plain_numeric_member and not has_generic_001_head:
            is_split_member = False
        has_split_companions = False
        is_split_exe_companion = False
        is_disguised_split_exe_companion = False

        if path_info["ext"] == ".exe":
            has_split_companions = self.has_split_companions_in_dir(filenames, path_info["base"])
            is_split_exe_companion = has_split_companions
        elif path_info["base"].lower().endswith(".exe"):
            logical_base = path_info["base"][:-4]
            has_split_companions = self.has_split_companions_in_dir(filenames, logical_base)
            is_disguised_split_exe_companion = has_split_companions

        match_rar_disguised = re.search(r"^(.*\.part)0*1\.rar(?:\.[^.]+)?$", filename, re.I)
        match_rar_head = re.search(r"^(.*\.part)0*1$", path_info["base"], re.I)
        match_001_head = re.search(r"^(.*)\.001$", path_info["base"], re.I)

        return FileRelation(
            root=path_info["root"],
            filename=path_info["filename"],
            path=path_info["path"],
            base=path_info["base"],
            ext=path_info["ext"],
            relative_path=self._normalize_relpath(self.engine._safe_relpath(path_info["path"], scan_root or root)),
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
        )

    def build_directory_relationships(self, root, files, scan_root=None):
        filenames = tuple(files)
        return {
            filename: self.build_file_relation(root, filename, filenames, scan_root=scan_root)
            for filename in filenames
        }
