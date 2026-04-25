from dataclasses import dataclass, field
from typing import Optional, List
from smart_unpacker.contracts.detection import FactBag


@dataclass
class SplitArchiveInfo:
    is_split: bool = False
    is_sfx_stub: bool = False
    parts: List[str] = field(default_factory=list)
    preferred_entry: str = ""
    source: str = ""


@dataclass
class RenameInstruction:
    kind: str  # "single" or "series"
    root: str
    source: Optional[str] = None
    target: Optional[str] = None
    prefix: Optional[str] = None
    separator: Optional[str] = None
    new_ext_suffix: Optional[str] = None

@dataclass
class ArchiveTask:
    fact_bag: FactBag
    score: int
    key: str = ""
    main_path: str = ""
    all_parts: Optional[List[str]] = None
    logical_name: str = ""
    split_info: SplitArchiveInfo = field(default_factory=SplitArchiveInfo)

    def __post_init__(self):
        if self.all_parts is None:
            self.all_parts = []
        if not self.main_path:
            self.main_path = self.fact_bag.get("file.path", "")
        if not self.logical_name:
            self.logical_name = self.fact_bag.get("file.logical_name", "")
        if not self.key:
            self.key = self.fact_bag.get("file.key") or self.logical_name or self.main_path
        if not self.all_parts and self.main_path:
            members = list(self.fact_bag.get("file.split_members", []) or [])
            self.all_parts = [self.main_path] + members
        if self.split_info is None:
            self.split_info = SplitArchiveInfo()
        if not self.split_info.parts and self.all_parts:
            self.split_info.parts = list(self.all_parts)
        if len(self.split_info.parts) > 1:
            self.split_info.is_split = True

    @classmethod
    def from_fact_bag(cls, fact_bag: FactBag, score: int) -> "ArchiveTask":
        main_path = fact_bag.get("file.path", "")
        members = list(fact_bag.get("file.split_members", []) or [])
        logical_name = fact_bag.get("file.logical_name") or ""
        if not logical_name and main_path:
            import os
            logical_name = os.path.splitext(os.path.basename(main_path))[0]
        key = fact_bag.get("file.key") or logical_name or main_path
        all_parts = [main_path] + members if main_path else members
        is_split = bool(
            members
            or fact_bag.get("relation.is_split_related")
            or fact_bag.get("file.is_split_candidate")
        )
        is_sfx_stub = bool(
            fact_bag.get("relation.is_split_exe_companion")
            or fact_bag.get("relation.is_disguised_split_exe_companion")
        )
        split_info = SplitArchiveInfo(
            is_split=is_split or len(all_parts) > 1,
            is_sfx_stub=is_sfx_stub,
            parts=list(all_parts),
            source="detection" if is_split or is_sfx_stub else "",
        )
        return cls(
            fact_bag=fact_bag,
            score=score,
            key=key,
            main_path=main_path,
            all_parts=all_parts,
            logical_name=logical_name,
            split_info=split_info,
        )

    def apply_path_mapping(self, path_map: dict[str, str]):
        if not path_map:
            return

        import os

        normalized_map = {
            os.path.normcase(os.path.normpath(old)): os.path.normpath(new)
            for old, new in path_map.items()
        }

        def mapped(path: str) -> str:
            return normalized_map.get(os.path.normcase(os.path.normpath(path)), path)

        self.main_path = mapped(self.main_path)
        self.all_parts = [mapped(path) for path in self.all_parts]
        self.split_info.parts = [mapped(path) for path in self.split_info.parts]
        if self.split_info.preferred_entry:
            self.split_info.preferred_entry = mapped(self.split_info.preferred_entry)
        self.fact_bag.set("file.path", self.main_path)
        self.fact_bag.set("file.split_members", [path for path in self.all_parts if path != self.main_path])
