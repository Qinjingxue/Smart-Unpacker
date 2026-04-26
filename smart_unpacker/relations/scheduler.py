from typing import Optional, Set

from smart_unpacker.contracts.filesystem import DirectorySnapshot
from smart_unpacker.relations.internal.group_builder import RelationsGroupBuilder
from smart_unpacker.relations.internal.models import CandidateGroup, FileRelation


class RelationsScheduler:
    """Public facade for relation grouping.

    The relation layer is intentionally a black box to callers: it receives a
    directory snapshot and returns logical archive candidates. Internal filename
    parsing, split expansion, and companion discovery live under
    smart_unpacker.relations.internal.
    """

    def __init__(self):
        self._builder = RelationsGroupBuilder()

    def build_candidate_groups(self, snapshot: DirectorySnapshot) -> list[CandidateGroup]:
        return self._builder.build_candidate_groups(snapshot)

    def detect_split_role(self, filename: str) -> Optional[str]:
        return self._builder.detect_split_role(filename)

    def get_logical_name(self, filename: str, is_archive: bool = False) -> str:
        return self._builder.get_logical_name(filename, is_archive=is_archive)

    def build_file_relation(self, filename: str, sibling_names: Set[str]) -> FileRelation:
        return self._builder.build_file_relation(filename, sibling_names)

    def parse_numbered_volume(self, path: str):
        return self._builder.parse_numbered_volume(path)

    def expand_misnamed_split_parts(self, archive: str, all_parts: list[str], directory_index=None) -> list[str]:
        return self._builder.expand_misnamed_split_parts(archive, all_parts, directory_index=directory_index)

    def collect_misnamed_volume_candidates(
        self,
        archive: str,
        all_parts: list[str],
        archive_prefix: str,
        style: str,
        directory_index=None,
    ) -> list[str]:
        return self._builder.collect_misnamed_volume_candidates(
            archive,
            all_parts,
            archive_prefix,
            style,
            directory_index=directory_index,
        )
