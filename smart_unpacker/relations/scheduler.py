from smart_unpacker.contracts.filesystem import DirectorySnapshot
from smart_unpacker.relations.internal.group_builder import RelationsGroupBuilder
from smart_unpacker.relations.internal.models import CandidateGroup


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

    def detect_split_role(self, filename: str) -> str | None:
        return self._builder.detect_split_role(filename)

    def logical_name_for_archive(self, filename: str) -> str:
        return self._builder.get_logical_name(filename, is_archive=True)

    def select_first_volume(self, paths: list[str]) -> str:
        return self._builder.select_first_volume(paths)

    def should_scan_split_siblings(self, archive: str, *, is_split: bool = False, is_sfx_stub: bool = False) -> bool:
        return self._builder.should_scan_split_siblings(archive, is_split=is_split, is_sfx_stub=is_sfx_stub)

    def find_standard_split_siblings(self, archive: str) -> list[str]:
        return self._builder.find_standard_split_siblings(archive)

    def parse_numbered_volume(self, path: str):
        return self._builder.parse_numbered_volume(path)
