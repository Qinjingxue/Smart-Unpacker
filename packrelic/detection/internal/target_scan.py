import os
from typing import List

from packrelic.contracts.detection import FactBag
from packrelic.detection.internal.scan_session import DetectionScanSession
from packrelic.relations.scheduler import RelationsScheduler
from packrelic.support.path_keys import normalized_path, path_key, safe_relative_path


RELATIONS = RelationsScheduler()


def _bag_paths(bag: FactBag) -> list[str]:
    paths = []
    main = bag.get("file.path")
    if main:
        paths.append(main)
    paths.extend(bag.get("file.split_members", []) or [])
    return [path_key(path) for path in paths if path]

def _bag_key(bag: FactBag) -> str:
    path = bag.get("file.path", "")
    if not bag.get("relation.is_split_related"):
        return path_key(path)
    parent = os.path.dirname(normalized_path(path)) if path else ""
    logical_name = bag.get("file.logical_name") or os.path.basename(path)
    return path_key(os.path.join(parent, logical_name.lower()))


def _add_unique(target: List[FactBag], seen_keys: set[str], bags: List[FactBag]):
    for bag in bags:
        key = _bag_key(bag)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        target.append(bag)


def build_fact_bags_for_target(target_path: str, session: DetectionScanSession | None = None) -> List[FactBag]:
    """Scan a selected file's parent so split-volume siblings remain visible."""
    return build_fact_bags_for_targets([target_path], session=session)


def build_fact_bags_for_targets(
    target_paths: List[str],
    session: DetectionScanSession | None = None,
    config: dict | None = None,
) -> List[FactBag]:
    session = session or DetectionScanSession(RELATIONS, config=config)
    selected_dirs: list[str] = []
    selected_files: list[str] = []

    for raw_path in target_paths:
        path = normalized_path(raw_path)
        if os.path.isdir(path):
            selected_dirs.append(path)
        elif os.path.isfile(path):
            selected_files.append(path)

    scan_roots = list(selected_dirs)
    for file_path in selected_files:
        if not any(safe_relative_path(file_path, directory) is not None for directory in selected_dirs):
            scan_roots.append(os.path.dirname(file_path) or os.getcwd())
    if hasattr(session, "set_scan_roots"):
        session.set_scan_roots(scan_roots)

    fact_bags: List[FactBag] = []
    seen_keys: set[str] = set()

    for directory in selected_dirs:
        _add_unique(fact_bags, seen_keys, session.fact_bags_for_directory(directory))

    for file_path in selected_files:
        if any(safe_relative_path(file_path, directory) is not None for directory in selected_dirs):
            continue

        parent = os.path.dirname(file_path) or os.getcwd()
        parent_bags = session.fact_bags_for_directory(parent)

        selected_key = path_key(file_path)
        matched = [
            bag for bag in parent_bags
            if selected_key in _bag_paths(bag)
        ]
        if not matched:
            expected_name = session.logical_name_for_archive(os.path.basename(file_path)).lower()
            matched = [
                bag for bag in parent_bags
                if bag.get("relation.is_split_related")
                and os.path.basename(bag.get("file.logical_name", "")).lower() == expected_name
            ]
        _add_unique(fact_bags, seen_keys, matched)

    return fact_bags
