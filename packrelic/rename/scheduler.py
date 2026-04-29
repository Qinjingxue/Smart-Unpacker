import os
import re
from collections import defaultdict
from typing import Callable, Dict, List, Set

from packrelic.contracts.tasks import ArchiveTask, RenameInstruction
from packrelic.rename.internal.volume_normalizer import SplitVolumeNormalizer, StagedSplit
from packrelic.support.path_keys import absolute_path_key, normalized_path


class RenameScheduler:
    def __init__(self):
        self.volume_normalizer = SplitVolumeNormalizer()

    def apply_renames(self, tasks: List[ArchiveTask]) -> Dict[str, str]:
        return self.execute(self.plan(tasks))

    def normalize_split_group(self, task: ArchiveTask, startupinfo=None) -> StagedSplit:
        return self.volume_normalizer.normalize(
            task.main_path,
            list(task.all_parts or [task.main_path]),
            startupinfo=startupinfo,
            volume_entries=list(task.split_info.volumes or []),
        )

    def normalize_archive_paths(
        self,
        entry_path: str,
        all_parts: list[str] | None = None,
        startupinfo=None,
        volume_entries: list[dict] | None = None,
    ) -> StagedSplit:
        return self.volume_normalizer.normalize(
            entry_path,
            list(all_parts or [entry_path]),
            startupinfo=startupinfo,
            volume_entries=volume_entries,
        )

    def cleanup_normalized_split_group(self, staged: StagedSplit):
        self.volume_normalizer.cleanup(staged)

    def build_output_dir_resolver(
        self,
        tasks: List[ArchiveTask],
        default_output_dir_for_task: Callable[[ArchiveTask], str],
    ) -> Callable[[ArchiveTask], str]:
        default_dirs = {id(task): default_output_dir_for_task(task) for task in tasks}
        by_output = defaultdict(list)
        for task in tasks:
            output_dir = default_dirs[id(task)]
            by_output[absolute_path_key(output_dir)].append(task)

        resolved_dirs = dict(default_dirs)
        reserved = {
            absolute_path_key(output_dir)
            for output_dir in default_dirs.values()
            if output_dir
        }
        for duplicate_tasks in by_output.values():
            if len(duplicate_tasks) <= 1:
                continue
            for task in duplicate_tasks:
                resolved_dirs[id(task)] = self._disambiguated_output_dir(
                    default_dirs[id(task)],
                    task,
                    reserved,
                )

        return lambda task: resolved_dirs[id(task)]

    def plan(self, tasks: List[ArchiveTask]) -> List[RenameInstruction]:
        instructions = []
        seen_series = set()

        for task in tasks:
            bag = task.fact_bag
            path = task.main_path
            if not path:
                continue

            root = os.path.dirname(path)
            filename = os.path.basename(path)
            base, ext = os.path.splitext(filename)
            ext = ext.lower()

            detected_ext = bag.get("file.detected_ext")
            probe_offset = bag.get("file.probe_offset")
            embedded_archive_found = bool(bag.get("file.embedded_archive_found"))
            embedded_analysis = bag.get("embedded_archive.analysis") or {}
            overlay_analysis = bag.get("pe.overlay_structure") or {}
            embedded_offset = max(
                int(embedded_analysis.get("offset") or 0),
                int(overlay_analysis.get("archive_offset") or 0),
            )
            split_role = bag.get("file.split_role")
            match_rar_disguised = bag.get("relation.match_rar_disguised")
            match_rar_head = bag.get("relation.match_rar_head")
            match_001_head = bag.get("relation.match_001_head")

            if match_rar_disguised is None:
                match_rar_disguised = re.search(r"^(.*\.part)0*1\.rar(?:\.[^.]+)?$", filename, re.IGNORECASE) is not None
            if match_rar_head is None:
                match_rar_head = re.search(r"^(.*\.part)0*1$", base, re.IGNORECASE) is not None
            if match_001_head is None:
                match_001_head = re.search(r"^(.*)\.001$", base, re.IGNORECASE) is not None

            if ext == ".exe":
                continue

            should_rename = False
            if match_rar_disguised:
                should_rename = True
            elif embedded_archive_found or embedded_offset > 0 or (probe_offset and probe_offset > 0):
                should_rename = False
            elif split_role and not match_rar_head and not match_001_head:
                should_rename = False
            elif detected_ext and ext != detected_ext:
                should_rename = True

            if not should_rename:
                continue

            target_ext = detected_ext

            if match_rar_disguised:
                prefix = re.search(r"^(.*\.part)0*1\.rar(?:\.[^.]+)?$", filename, re.IGNORECASE).group(1)
                series_key = (root, prefix.lower(), "", ".rar")
                if series_key not in seen_series:
                    seen_series.add(series_key)
                    instructions.append(RenameInstruction(
                        kind="series", root=root, prefix=prefix, separator="", new_ext_suffix=".rar"
                    ))
                continue

            if match_rar_head:
                prefix = re.search(r"^(.*\.part)0*1$", base, re.IGNORECASE).group(1)
                series_key = (root, prefix.lower(), "", target_ext or "")
                if series_key not in seen_series:
                    seen_series.add(series_key)
                    instructions.append(RenameInstruction(
                        kind="series", root=root, prefix=prefix, separator="", new_ext_suffix=target_ext or ""
                    ))
                continue

            if match_001_head:
                prefix = re.search(r"^(.*)\.001$", base, re.IGNORECASE).group(1)
                series_key = (root, prefix.lower(), ".", "")
                if series_key not in seen_series:
                    seen_series.add(series_key)
                    instructions.append(RenameInstruction(
                        kind="series", root=root, prefix=prefix, separator=".", new_ext_suffix=""
                    ))
                continue

            if target_ext:
                if base.lower().endswith(target_ext.lower()):
                    new_name = base
                else:
                    new_name = base + target_ext
                instructions.append(RenameInstruction(
                    kind="single", root=root, source=filename, target=new_name
                ))

        return instructions

    def execute(self, instructions: List[RenameInstruction]) -> Dict[str, str]:
        processed_paths: Set[str] = set()
        path_map: Dict[str, str] = {}

        for instruction in instructions:
            if instruction.kind == "series":
                self._rename_series(instruction, processed_paths, path_map)
            else:
                self._rename_single(instruction, processed_paths, path_map)

        return path_map

    def _rename_series(self, instruction: RenameInstruction, processed_set: Set[str], path_map: Dict[str, str]):
        root = instruction.root
        prefix = instruction.prefix
        separator = instruction.separator
        new_ext_suffix = instruction.new_ext_suffix

        if new_ext_suffix and new_ext_suffix.lower() == ".rar" and ".part" in prefix.lower():
            pattern = re.escape(prefix) + r"\d+\.rar(?:\.[^.]+)?$"
            normalizer_pattern = r"^(" + re.escape(prefix) + r"\d+\.rar)(?:\.[^.]+)?$"
        else:
            pattern = re.escape(prefix) + re.escape(separator) + r"\d+(?:\.[^.]+)?$"
            normalizer_pattern = r"^(" + re.escape(prefix) + re.escape(separator) + r"\d+)(?:\.[^.]+)?$"

        try:
            files = os.listdir(root)
        except OSError:
            return

        for filename in files:
            if re.match(pattern, filename, re.IGNORECASE):
                old_path = normalized_path(os.path.join(root, filename))
                if old_path in processed_set:
                    continue

                normalized_name = re.sub(normalizer_pattern, r"\1", filename, flags=re.IGNORECASE)
                if new_ext_suffix and normalized_name.lower().endswith(new_ext_suffix.lower()):
                    new_name = normalized_name
                else:
                    new_name = normalized_name if not new_ext_suffix else normalized_name + new_ext_suffix

                new_path = normalized_path(os.path.join(root, new_name))
                if not os.path.exists(new_path) or old_path.lower() == new_path.lower():
                    if old_path.lower() != new_path.lower():
                        print(f"[RENAME] Fixing series: {filename} -> {new_name}")
                        try:
                            os.rename(old_path, new_path)
                            path_map[old_path] = new_path
                            processed_set.add(new_path)
                        except Exception as exc:
                            print(f"[ERROR] Failed to rename series file: {filename} ({exc})")
                    else:
                        processed_set.add(old_path)

    def _rename_single(self, instruction: RenameInstruction, processed_set: Set[str], path_map: Dict[str, str]):
        root = instruction.root
        source_name = instruction.source
        target_name = instruction.target

        old_path = normalized_path(os.path.join(root, source_name))
        if old_path in processed_set:
            return

        new_path = normalized_path(os.path.join(root, target_name))
        if not os.path.exists(new_path) or old_path.lower() == new_path.lower():
            if old_path.lower() != new_path.lower():
                print(f"[RENAME] Fixing extension: {source_name} -> {target_name}")
                try:
                    os.rename(old_path, new_path)
                    path_map[old_path] = new_path
                    processed_set.add(new_path)
                except Exception as exc:
                    print(f"[ERROR] Failed to rename file: {source_name} ({exc})")
            else:
                processed_set.add(old_path)

    def _disambiguated_output_dir(self, default_dir: str, task: ArchiveTask, reserved: set[str]) -> str:
        archive_ext = os.path.splitext(task.main_path)[1].lstrip(".").lower() or "archive"
        parent = os.path.dirname(default_dir)
        base = os.path.basename(default_dir)
        candidate = os.path.join(parent, f"{base}_{archive_ext}")
        index = 2
        while absolute_path_key(candidate) in reserved or os.path.isfile(candidate):
            candidate = os.path.join(parent, f"{base}_{archive_ext}_{index}")
            index += 1
        reserved.add(absolute_path_key(candidate))
        return candidate
