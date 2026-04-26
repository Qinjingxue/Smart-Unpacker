from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from smart_unpacker.contracts.filesystem import FileEntry


@dataclass
class FileRelation:
    filename: str
    logical_name: str
    split_role: Optional[str] = None
    is_split_member: bool = False
    has_generic_001_head: bool = False
    is_plain_numeric_member: bool = False
    has_split_companions: bool = False
    is_split_exe_companion: bool = False
    is_disguised_split_exe_companion: bool = False
    is_split_related: bool = False
    match_rar_disguised: bool = False
    match_rar_head: bool = False
    match_001_head: bool = False
    split_family: str = ""
    split_index: int = 0


@dataclass
class CandidateGroup:
    head_path: str
    logical_name: str
    relation: FileRelation
    member_paths: List[str]
    is_split_candidate: bool = False
    head_size: int | None = None

    @property
    def kind(self) -> str:
        return "split_archive" if self.is_split_candidate or self.relation.is_split_related else "file"

    @property
    def entry_path(self) -> str:
        return self.head_path

    @property
    def all_paths(self) -> List[str]:
        return [self.head_path] + list(self.member_paths)


@dataclass
class DirectoryFileIndex:
    entries: List[FileEntry]
    lower_names: Set[str]
    by_norm_path: Dict[str, FileEntry]
    by_lower_name: Dict[str, List[FileEntry]]
