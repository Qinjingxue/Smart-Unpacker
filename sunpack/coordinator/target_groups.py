from typing import List

from sunpack.contracts.detection import FactBag
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.filesystem import DirectorySnapshot
from sunpack.relations.scheduler import CandidateGroup, RelationsScheduler
from sunpack.filesystem.directory_scanner import DirectoryScanner


def relation_group_to_fact_bag(group: CandidateGroup) -> FactBag:
    bag = FactBag()
    relation = group.relation
    all_paths = group.all_paths
    member_paths = [path for path in all_paths if path != group.head_path]
    bag.set("file.path", group.head_path)
    bag.set("file.logical_name", group.logical_name)
    bag.set("candidate.kind", group.kind)
    bag.set("candidate.entry_path", group.entry_path)
    bag.set("candidate.member_paths", all_paths)
    bag.set("candidate.logical_name", group.logical_name)
    source_descriptor = ArchiveInputDescriptor.from_parts(
        archive_path=group.entry_path,
        part_paths=all_paths,
        logical_name=group.logical_name,
    )
    state = ArchiveState.from_archive_input(source_descriptor)
    bag.set("archive.state", state.to_dict())
    bag.set("archive.source", state.source.to_dict())
    bag.set("archive.patch_stack", [])
    bag.set("archive.patch_digest", state.effective_patch_digest())
    if isinstance(group.head_size, int):
        bag.set("file.size", group.head_size)
    bag.set("file.split_members", list(member_paths))
    bag.set("file.split_role", relation.split_role)
    bag.set("file.is_split_candidate", group.is_split_candidate or relation.is_split_related)
    bag.set("relation.is_split_related", group.is_split_candidate or relation.is_split_related)
    bag.set("relation.is_split_member", relation.is_split_member)
    bag.set("relation.has_split_companions", relation.has_split_companions)
    bag.set("relation.is_split_exe_companion", relation.is_split_exe_companion)
    bag.set("relation.is_disguised_split_exe_companion", relation.is_disguised_split_exe_companion)
    bag.set("relation.has_generic_001_head", relation.has_generic_001_head)
    bag.set("relation.is_plain_numeric_member", relation.is_plain_numeric_member)
    bag.set("relation.match_rar_disguised", relation.match_rar_disguised)
    bag.set("relation.match_rar_head", relation.match_rar_head)
    bag.set("relation.match_001_head", relation.match_001_head)
    bag.set("relation.split_entry_path", group.head_path)
    bag.set("relation.split_member_count", len(all_paths) if group.is_split_candidate else 0)
    if group.split_group_complete is not None:
        bag.set("relation.split_group_complete", bool(group.split_group_complete))
    else:
        bag.set("relation.split_group_complete", True)
    if group.split_missing_reason:
        bag.set("relation.split_missing_reason", group.split_missing_reason)
    if group.split_missing_indices:
        bag.set("relation.split_missing_indices", list(group.split_missing_indices))
    bag.set("relation.split_family", relation.split_family)
    bag.set("relation.split_index", relation.split_index)
    bag.set("relation.split_is_first", relation.split_role == "first")
    _inject_scene_metadata(bag, group.head_metadata or {})
    if group.split_volumes:
        bag.set("relation.split_volumes", [
            {
                "path": volume.path,
                "number": volume.number,
                "role": volume.role,
                "source": volume.source,
                "style": volume.style,
                "prefix": volume.prefix,
                "width": volume.width,
            }
            for volume in group.split_volumes
        ])
    if member_paths:
        bag.set("relation.member_paths", list(member_paths))
    return bag


def _inject_scene_metadata(bag: FactBag, metadata: dict) -> None:
    scene = metadata.get("scene") if isinstance(metadata, dict) else None
    if not isinstance(scene, dict):
        return
    for key, value in scene.items():
        if key == "context":
            bag.set("scene.context", value if isinstance(value, dict) else {})
        elif key.startswith("scene."):
            bag.set(key, value)
        else:
            bag.set(f"scene.{key}", value)
    if bag.get("scene.is_protected_path") and not bag.get("scene.is_runtime_exact_path"):
        bag.set(
            "scene.is_runtime_resource_archive",
            bool(bag.get("scene.protected_archive_ext_match") or bag.get("relation.is_split_related")),
        )


def build_candidate_fact_bags(directory: str, relations: RelationsScheduler | None = None) -> List[FactBag]:
    scheduler = relations or RelationsScheduler()
    snapshot = DirectoryScanner(directory).scan()
    return build_candidate_fact_bags_from_snapshot(snapshot, scheduler)


def build_candidate_fact_bags_from_snapshot(
    snapshot: DirectorySnapshot,
    relations: RelationsScheduler | None = None,
) -> List[FactBag]:
    scheduler = relations or RelationsScheduler()
    return [relation_group_to_fact_bag(group) for group in scheduler.build_candidate_groups(snapshot)]
