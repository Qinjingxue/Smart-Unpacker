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
    decision: str = "archive"
    stop_reason: str = ""
    matched_rules: List[str] = field(default_factory=list)
    detected_ext: str = ""

    def __post_init__(self):
        self.all_parts = list(self.all_parts or [])
        if not self.main_path:
            raise ValueError("ArchiveTask.main_path is required")
        if not self.key:
            self.key = self.logical_name or self.main_path
        if self.split_info is None:
            self.split_info = SplitArchiveInfo()
        if not self.split_info.parts and self.all_parts:
            self.split_info.parts = list(self.all_parts)
        if len(self.split_info.parts) > 1:
            self.split_info.is_split = True

    @classmethod
    def from_fact_bag(cls, fact_bag: FactBag, score: int, decision=None) -> "ArchiveTask":
        main_path = fact_bag.get("candidate.entry_path") or ""
        all_parts = list(fact_bag.get("candidate.member_paths") or [])
        logical_name = fact_bag.get("candidate.logical_name") or ""
        key = logical_name or main_path
        is_split = bool(
            fact_bag.get("relation.is_split_related")
            or fact_bag.get("candidate.kind") == "split_archive"
            or len(all_parts) > 1
        )
        is_sfx_stub = bool(
            fact_bag.get("relation.is_split_exe_companion")
            or fact_bag.get("relation.is_disguised_split_exe_companion")
        )
        split_info = SplitArchiveInfo(
            is_split=is_split or len(all_parts) > 1,
            is_sfx_stub=is_sfx_stub,
            parts=list(all_parts),
            preferred_entry="",
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
            decision=getattr(decision, "decision", "archive"),
            stop_reason=getattr(decision, "stop_reason", "") or "",
            matched_rules=list(getattr(decision, "matched_rules", []) or []),
            detected_ext=fact_bag.get("file.detected_ext", ""),
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
        self.fact_bag.set("candidate.entry_path", self.main_path)
        self.fact_bag.set("candidate.member_paths", list(self.all_parts))
        self.fact_bag.set("file.split_members", [path for path in self.all_parts if path != self.main_path])
