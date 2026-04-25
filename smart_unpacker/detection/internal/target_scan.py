import os
from typing import List

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection.internal.scan_session import DetectionScanSession
from smart_unpacker.relations.scheduler import RelationsScheduler


RELATIONS = RelationsScheduler()


def _bag_paths(bag: FactBag) -> list[str]:
    paths = []
    main = bag.get("file.path")
    if main:
        paths.append(main)
    paths.extend(bag.get("file.split_members", []) or [])
    return [os.path.normcase(os.path.normpath(path)) for path in paths if path]

def _bag_key(bag: FactBag) -> str:
    path = bag.get("file.path", "")
    parent = os.path.dirname(os.path.normpath(path)) if path else ""
    logical_name = bag.get("file.logical_name") or os.path.basename(path)
    return os.path.normcase(os.path.join(parent, logical_name.lower()))


def _safe_relpath(path: str, start: str) -> str | None:
    try:
        rel = os.path.relpath(os.path.normpath(path), os.path.normpath(start))
    except ValueError:
        return None
    if rel == "." or rel.startswith(".."):
        return None
    return rel


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
        path = os.path.normpath(raw_path)
        if os.path.isdir(path):
            selected_dirs.append(path)
        elif os.path.isfile(path):
            selected_files.append(path)

    fact_bags: List[FactBag] = []
    seen_keys: set[str] = set()

    for directory in selected_dirs:
        _add_unique(fact_bags, seen_keys, session.fact_bags_for_directory(directory))

    for file_path in selected_files:
        if any(_safe_relpath(file_path, directory) is not None for directory in selected_dirs):
            continue

        parent = os.path.dirname(file_path) or os.getcwd()
        parent_bags = session.fact_bags_for_directory(parent)

        selected_key = os.path.normcase(os.path.normpath(file_path))
        expected_name = session.logical_name_for_archive(os.path.basename(file_path)).lower()
        matched = [
            bag for bag in parent_bags
            if os.path.basename(bag.get("file.logical_name", "")).lower() == expected_name
        ]
        if not matched:
            matched = [bag for bag in parent_bags if selected_key in _bag_paths(bag)]
        _add_unique(fact_bags, seen_keys, matched)

    return fact_bags
