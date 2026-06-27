from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict

from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.relations.scheduler import RelationsScheduler
from sunpack.support.path_keys import path_key

from sunpack.filesystem.watcher.group_models import WatchGroupSnapshot


class WatchGroupCoordinator:
    """Resolve stable file events to canonical split-archive groups."""

    def __init__(self, config: dict):
        self.config = config
        self.relations = RelationsScheduler()

    def resolve_paths(self, paths: list[str]) -> dict[str, WatchGroupSnapshot | None]:
        by_directory: dict[str, list[str]] = defaultdict(list)
        for path in paths:
            by_directory[os.path.dirname(os.path.abspath(path))].append(os.path.abspath(path))

        resolved: dict[str, WatchGroupSnapshot | None] = {}
        for directory, directory_paths in by_directory.items():
            groups = DetectionScanSession(self.relations, config=self.config).relation_groups_for_directory(directory)
            snapshots = [self._snapshot(group, directory) for group in groups if group.kind == "split_archive"]
            snapshots.extend(self._orphan_snapshots(directory, snapshots))
            for path in directory_paths:
                selected = next(
                    (snapshot for snapshot in snapshots if path_key(path) in {path_key(item) for item in snapshot.member_paths}),
                    None,
                )
                resolved[path_key(path)] = selected
        return resolved

    def _orphan_snapshots(
        self,
        directory: str,
        relation_snapshots: list[WatchGroupSnapshot],
    ) -> list[WatchGroupSnapshot]:
        assigned = {path_key(path) for snapshot in relation_snapshots for path in snapshot.member_paths}
        numbered: dict[tuple[str, str, int], list[tuple[str, int]]] = defaultdict(list)
        old_rar: dict[str, list[tuple[str, int]]] = defaultdict(list)
        try:
            names = os.listdir(directory)
        except OSError:
            return []
        for name in names:
            path = os.path.abspath(os.path.join(directory, name))
            if path_key(path) in assigned or not os.path.isfile(path):
                continue
            parsed = self.relations.parse_numbered_volume(path)
            if parsed and parsed.get("style") in {"plain_numeric_suffix", "numeric_suffix"}:
                key = (str(parsed["prefix"]), str(parsed["style"]), int(parsed.get("width") or 3))
                numbered[key].append((path, int(parsed["number"])))
                continue
            match = re.match(r"^(?P<prefix>.+)\.r(?P<number>\d{2,3})$", path, re.IGNORECASE)
            if match:
                old_rar[str(match.group("prefix"))].append((path, int(match.group("number")) + 2))

        output: list[WatchGroupSnapshot] = []
        for (prefix, style, width), values in numbered.items():
            numbers = sorted(number for _path, number in values)
            strong_plain_sequence = len(numbers) >= 2 and numbers == list(range(numbers[0], numbers[-1] + 1))
            if 1 in numbers or (style == "plain_numeric_suffix" and not strong_plain_sequence):
                continue
            prefix_name = os.path.basename(prefix)
            if style == "numeric_suffix":
                archive_ext = os.path.splitext(prefix_name)[1].lower().lstrip(".")
                family = f"{archive_ext}_numbered" if archive_ext else "generic_numbered"
                logical_name = os.path.splitext(prefix_name)[0] if archive_ext else prefix_name
            else:
                family = "generic_numbered"
                logical_name = prefix_name
            output.append(self._missing_head_snapshot(
                directory=directory,
                logical_name=logical_name,
                split_family=family,
                members=[path for path, _number in sorted(values, key=lambda item: item[1])],
                expected_head=f"{prefix}.{1:0{width}d}",
                sources=[style] * len(values),
                missing_indices=[1],
            ))
        for prefix, values in old_rar.items():
            numbers = sorted(number for _path, number in values)
            expected_head = f"{prefix}.rar"
            missing_indices = ([] if os.path.isfile(expected_head) else [1]) + [
                number for number in range(2, numbers[-1] + 1) if number not in numbers
            ]
            output.append(self._missing_head_snapshot(
                directory=directory,
                logical_name=os.path.basename(prefix),
                split_family="rar_old",
                members=[path for path, _number in sorted(values, key=lambda item: item[1])],
                expected_head=expected_head,
                sources=["rar_old"] * len(values),
                missing_indices=missing_indices,
            ))
        return output

    def _missing_head_snapshot(
        self,
        *,
        directory: str,
        logical_name: str,
        split_family: str,
        members: list[str],
        expected_head: str,
        sources: list[str],
        missing_indices: list[int],
    ) -> WatchGroupSnapshot:
        head_exists = os.path.isfile(expected_head)
        all_members = ([os.path.abspath(expected_head)] if head_exists else []) + members
        complete = not missing_indices
        missing_reason = "missing_head" if 1 in missing_indices else "missing_middle" if missing_indices else ""
        group_id = _group_id(directory, logical_name, split_family)
        payload = {
            "group_id": group_id,
            "members": [_file_version(path) for path in all_members],
            "complete": complete,
            "missing_reason": missing_reason,
            "missing_indices": missing_indices,
            "sources": sources,
        }
        return WatchGroupSnapshot(
            group_id=group_id,
            directory=os.path.abspath(directory),
            logical_name=logical_name,
            split_family=split_family,
            head_path=os.path.abspath(expected_head) if head_exists else "",
            member_paths=tuple(os.path.abspath(path) for path in all_members),
            fingerprint=_fingerprint(payload),
            complete=complete,
            missing_reason=missing_reason,
            missing_indices=tuple(missing_indices),
        )

    def resolve_head(self, head_path: str) -> WatchGroupSnapshot | None:
        return self.resolve_paths([head_path]).get(path_key(head_path))

    def _snapshot(self, group, directory: str) -> WatchGroupSnapshot:
        volumes = list(group.split_volumes or [])
        first = next((volume for volume in volumes if volume.number == 1), None)
        head_path = os.path.abspath(first.path) if first is not None else ""
        members = tuple(os.path.abspath(path) for path in group.all_paths)
        split_family = str(group.relation.split_family or (volumes[0].style if volumes else "split"))
        group_id = _group_id(directory, group.logical_name, split_family)
        payload = {
            "group_id": group_id,
            "members": [_file_version(path) for path in members],
            "complete": group.split_group_complete,
            "missing_reason": group.split_missing_reason,
            "missing_indices": list(group.split_missing_indices or []),
            "sources": [str(volume.source) for volume in volumes],
        }
        fingerprint = _fingerprint(payload)
        return WatchGroupSnapshot(
            group_id=group_id,
            directory=os.path.abspath(directory),
            logical_name=str(group.logical_name),
            split_family=split_family,
            head_path=head_path,
            member_paths=members,
            fingerprint=fingerprint,
            complete=group.split_group_complete,
            missing_reason=str(group.split_missing_reason or ""),
            missing_indices=tuple(int(value) for value in (group.split_missing_indices or [])),
            candidate_substitution=group.split_group_complete is None,
        )


def _group_id(directory: str, logical_name: str, split_family: str) -> str:
    raw = "|".join((path_key(directory), split_family.lower(), logical_name.lower()))
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _fingerprint(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _file_version(path: str) -> tuple[str, int, int]:
    try:
        stat = os.stat(path)
    except OSError:
        return path_key(path), 0, 0
    return path_key(path), int(stat.st_size), int(stat.st_mtime_ns)
