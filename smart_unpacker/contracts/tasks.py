from dataclasses import dataclass, field
from typing import Optional, List
from smart_unpacker.contracts.archive_input import (
    ArchiveDescriptor,
    ArchiveFormatState,
    ArchiveInputDescriptor,
    ArchiveIntegrityState,
    ArchiveRelationState,
    ArchiveRepairState,
)
from smart_unpacker.contracts.archive_state import ArchiveState
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.support.path_keys import normalized_path, path_key


@dataclass
class SplitArchiveInfo:
    is_split: bool = False
    is_sfx_stub: bool = False
    parts: List[str] = field(default_factory=list)
    preferred_entry: str = ""
    source: str = ""
    volumes: List[dict] = field(default_factory=list)


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
        is_split = bool(
            fact_bag.get("relation.is_split_related")
            or fact_bag.get("candidate.kind") == "split_archive"
            or len(all_parts) > 1
        )
        key = logical_name if is_split else main_path
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
            volumes=list(fact_bag.get("relation.split_volumes") or []),
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
        ).ensure_archive_state()

    def apply_path_mapping(self, path_map: dict[str, str]):
        if not path_map:
            return

        normalized_map = {
            path_key(old): normalized_path(new)
            for old, new in path_map.items()
        }

        def mapped(path: str) -> str:
            return normalized_map.get(path_key(path), path)

        self.main_path = mapped(self.main_path)
        self.all_parts = [mapped(path) for path in self.all_parts]
        self.split_info.parts = [mapped(path) for path in self.split_info.parts]
        self.split_info.volumes = [
            {**volume, "path": mapped(str(volume.get("path") or ""))}
            for volume in self.split_info.volumes
            if isinstance(volume, dict)
        ]
        if self.split_info.preferred_entry:
            self.split_info.preferred_entry = mapped(self.split_info.preferred_entry)
        self.fact_bag.set("file.path", self.main_path)
        self.fact_bag.set("candidate.entry_path", self.main_path)
        self.fact_bag.set("candidate.member_paths", list(self.all_parts))
        self.fact_bag.set("file.split_members", [path for path in self.all_parts if path != self.main_path])
        if self.split_info.volumes:
            self.fact_bag.set("relation.split_volumes", list(self.split_info.volumes))
        raw_archive_state = self.fact_bag.get("archive.state")
        if isinstance(raw_archive_state, dict):
            self.set_archive_state(self.archive_state().with_path_mapping(mapped))
        elif isinstance(self.fact_bag.get("archive.input"), dict):
            self.set_archive_input(self.archive_input().with_path_mapping(mapped))

    def archive_input(self) -> ArchiveInputDescriptor:
        raw_state = self.fact_bag.get("archive.state")
        if isinstance(raw_state, dict):
            return ArchiveState.from_any(
                raw_state,
                archive_path=self.main_path,
                part_paths=list(self.all_parts or [self.main_path]),
                format_hint=self._format_hint(),
                logical_name=str(self.logical_name or ""),
            ).to_archive_input_descriptor()
        return ArchiveInputDescriptor.from_any(
            self.fact_bag.get("archive.input"),
            archive_path=self.main_path,
            part_paths=list(self.all_parts or [self.main_path]),
            format_hint=self._format_hint(),
            logical_name=str(self.logical_name or ""),
        )

    def archive_state(self) -> ArchiveState:
        return ArchiveState.from_any(
            self.fact_bag.get("archive.state"),
            archive_path=self.main_path,
            part_paths=list(self.all_parts or [self.main_path]),
            format_hint=self._format_hint(),
            logical_name=str(self.logical_name or ""),
            archive_input=self.fact_bag.get("archive.input"),
        )

    def ensure_archive_state(self) -> "ArchiveTask":
        if not isinstance(self.fact_bag.get("archive.state"), dict):
            self.set_archive_state(self.archive_state(), sync_compat=False)
        return self

    def set_archive_input(self, descriptor: ArchiveInputDescriptor | dict, *, sync_compat: bool = True) -> None:
        if isinstance(descriptor, dict):
            descriptor = ArchiveInputDescriptor.from_any(
                descriptor,
                archive_path=self.main_path,
                part_paths=list(self.all_parts or [self.main_path]),
                format_hint=self._format_hint(),
                logical_name=str(self.logical_name or ""),
            )
        self.fact_bag.set("archive.input", descriptor.to_dict())
        self.fact_bag.set("archive.descriptor.source", descriptor.to_dict())
        self._store_archive_state(ArchiveState.from_archive_input(descriptor), sync_compat=False)
        if not sync_compat:
            return
        self._sync_descriptor_compat(descriptor)

    def set_archive_state(self, state: ArchiveState | dict, *, sync_compat: bool = False) -> None:
        if isinstance(state, dict):
            state = ArchiveState.from_any(
                state,
                archive_path=self.main_path,
                part_paths=list(self.all_parts or [self.main_path]),
                format_hint=self._format_hint(),
                logical_name=str(self.logical_name or ""),
                archive_input=self.fact_bag.get("archive.input"),
            )
        self._store_archive_state(state, sync_compat=sync_compat)

    def _store_archive_state(self, state: ArchiveState, *, sync_compat: bool) -> None:
        self.fact_bag.set("archive.state", state.to_dict())
        self.fact_bag.set("archive.source", state.source.to_dict())
        self.fact_bag.set("archive.patch_stack", [patch.to_dict() for patch in state.patches])
        self.fact_bag.set("archive.patch_digest", state.effective_patch_digest())
        if sync_compat:
            descriptor = state.to_archive_input_descriptor()
            self.fact_bag.set("archive.input", descriptor.to_dict())
            self.fact_bag.set("archive.descriptor.source", descriptor.to_dict())
            self._sync_descriptor_compat(descriptor)

    def _sync_descriptor_compat(self, descriptor: ArchiveInputDescriptor) -> None:
        if descriptor.format_hint:
            self.fact_bag.set("archive.format_hint", descriptor.format_hint)

    def archive_descriptor(self) -> ArchiveDescriptor:
        source = self.archive_state().to_archive_input_descriptor()
        selected_format = str(self.fact_bag.get("analysis.selected_format") or "")
        confidence = 0.0
        evidence = self.fact_bag.get("analysis.segment")
        if isinstance(evidence, dict):
            confidence = float(evidence.get("confidence", 0.0) or 0.0)
        damage_flags = []
        if isinstance(evidence, dict):
            damage_flags.extend(evidence.get("damage_flags") or [])
        repair_rounds = self.fact_bag.get("repair.loop.rounds")
        relation = ArchiveRelationState(
            kind=str(self.fact_bag.get("candidate.kind") or ("split_archive" if self.split_info.is_split else "file")),
            is_split=bool(self.split_info.is_split),
            is_sfx=bool(self.split_info.is_sfx_stub),
            volumes_complete=self.fact_bag.get("relation.split_group_complete"),
            missing_indices=list(self.fact_bag.get("relation.split_missing_indices") or []),
            missing_reason=str(self.fact_bag.get("relation.split_missing_reason") or ""),
        )
        return ArchiveDescriptor(
            id=str(self.key or self.main_path),
            logical_name=str(self.logical_name or ""),
            source=source,
            format=ArchiveFormatState(
                detected=str(self.detected_ext or ""),
                selected=selected_format,
                hint=source.format_hint,
                confidence=confidence,
                status=str(self.fact_bag.get("analysis.status") or ""),
            ),
            relation=relation,
            integrity=ArchiveIntegrityState(damage_flags=_dedupe([str(item) for item in damage_flags])),
            repair=ArchiveRepairState(
                repaired=bool(self.fact_bag.get("archive.repaired")),
                rounds=list(repair_rounds) if isinstance(repair_rounds, list) else [],
                terminal_reason=str(self.fact_bag.get("repair.loop.terminal_reason") or ""),
            ),
        )

    def _format_hint(self) -> str:
        return str(
            self.fact_bag.get("archive.format_hint")
            or self.fact_bag.get("analysis.selected_format")
            or self.detected_ext
            or ""
        ).lstrip(".")


def _dedupe(values: list[str]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
