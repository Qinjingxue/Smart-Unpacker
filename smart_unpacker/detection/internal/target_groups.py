from typing import List

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.filesystem import DirectorySnapshot
from smart_unpacker.relations.scheduler import CandidateGroup, RelationsScheduler
from smart_unpacker.filesystem.directory_scanner import DirectoryScanner


def relation_group_to_fact_bag(group: CandidateGroup) -> FactBag:
    bag = FactBag()
    relation = group.relation
    bag.set("file.path", group.head_path)
    bag.set("file.logical_name", group.logical_name)
    bag.set("candidate.kind", group.kind)
    bag.set("candidate.entry_path", group.entry_path)
    bag.set("candidate.member_paths", group.all_paths)
    bag.set("candidate.logical_name", group.logical_name)
    if isinstance(group.head_size, int):
        bag.set("file.size", group.head_size)
    bag.set("file.split_members", list(group.member_paths))
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
    bag.set("relation.split_member_count", len(group.member_paths) + 1 if group.is_split_candidate else 0)
    bag.set("relation.split_group_complete", True)
    bag.set("relation.split_family", relation.split_family)
    bag.set("relation.split_index", relation.split_index)
    bag.set("relation.split_is_first", relation.split_role == "first")
    if group.member_paths:
        bag.set("relation.member_paths", list(group.member_paths))
    return bag


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
