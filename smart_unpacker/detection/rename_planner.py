from __future__ import annotations

import os
import re

from smart_unpacker.support.types import RenameInstruction


class RenamePlanner:
    def __init__(self, engine):
        self.engine = engine

    def _filename_needs_precheck(self, filename):
        lower_name = filename.lower()
        _, ext = os.path.splitext(lower_name)
        if ext == ".exe":
            return True
        if self.engine._detect_filename_split_role(lower_name) is not None:
            return True
        if self.engine._looks_like_disguised_archive_name(lower_name):
            return True
        if ext in self.engine.STANDARD_EXTS:
            return True
        return False

    def directory_may_need_precheck(self, target_dir):
        for _root, _dirs, files in os.walk(target_dir):
            for filename in files:
                if self._filename_needs_precheck(filename):
                    return True
        return False

    def should_plan_rename(self, info, relation):
        if relation.is_disguised_split_exe_companion or relation.match_rar_disguised:
            return True
        if info.probe_offset:
            return False
        if relation.ext == ".exe":
            return False
        if relation.is_split_related and not relation.match_rar_head and not relation.match_001_head:
            return False
        return bool(info.detected_ext) and info.decision == "archive" and relation.ext != info.detected_ext

    def resolve_target_ext(self, info, relation):
        detected_ext = info.detected_ext
        if relation.is_disguised_split_exe_companion and not detected_ext:
            return ".exe"
        return detected_ext

    def make_single_rename_instruction(self, relation, target_ext):
        if not target_ext:
            return None
        if relation.base.lower().endswith(target_ext.lower()):
            new_name = relation.base
        else:
            new_name = relation.base + target_ext
        return RenameInstruction(kind="single", root=relation.root, source=relation.filename, target=new_name)

    def make_series_rename_instruction(self, relation, target_ext):
        if relation.match_rar_disguised:
            return RenameInstruction(
                kind="series",
                root=relation.root,
                prefix=relation.match_rar_disguised.group(1),
                separator="",
                new_ext_suffix=".rar",
            )
        if relation.match_rar_head:
            return RenameInstruction(
                kind="series",
                root=relation.root,
                prefix=relation.match_rar_head.group(1),
                separator="",
                new_ext_suffix=target_ext or "",
            )
        if relation.match_001_head:
            return RenameInstruction(
                kind="series",
                root=relation.root,
                prefix=relation.match_001_head.group(1),
                separator=".",
                new_ext_suffix="",
            )
        return None

    def build_rename_plan_for_entry(self, relation, scene_context):
        info = self.engine.inspect_archive_candidate(relation.path, relation=relation, scene_context=scene_context)
        if not self.should_plan_rename(info, relation):
            if info.decision == "maybe_archive":
                self.engine.log(
                    f"[PRE-CHECK] 保守跳过: {relation.filename} | 分数={info.score} | {'; '.join(info.reasons[-2:])}"
                )
            return []

        target_ext = self.resolve_target_ext(info, relation)
        if not target_ext and not relation.match_rar_disguised:
            return []

        series_instruction = self.make_series_rename_instruction(relation, target_ext)
        if series_instruction:
            return [series_instruction]

        single_instruction = self.make_single_rename_instruction(relation, target_ext)
        return [single_instruction] if single_instruction else []

    def build_rename_plan(self, target_dir, scene_context):
        rename_plan = []
        seen_series = set()
        for root, _, files in os.walk(target_dir):
            root_scene_context = self.engine.scene_analyzer.resolve_scene_context_for_path(root, target_dir)
            relations = self.engine.relation_builder.build_directory_relationships(root, files, scan_root=target_dir)
            for filename in files:
                relation = relations[filename]
                for instruction in self.build_rename_plan_for_entry(relation, root_scene_context):
                    if instruction.kind == "series":
                        series_key = (
                            instruction.root,
                            instruction.prefix.lower(),
                            instruction.separator,
                            instruction.new_ext_suffix.lower(),
                        )
                        if series_key in seen_series:
                            continue
                        seen_series.add(series_key)
                    rename_plan.append(instruction)
        return rename_plan

    def rename_series(self, root, prefix, separator, new_ext_suffix, processed_set):
        if new_ext_suffix.lower() == ".rar" and ".part" in prefix.lower():
            pattern = re.escape(prefix) + r"\d+\.rar(?:\.[^.]+)?$"
            normalizer_pattern = r"^(" + re.escape(prefix) + r"\d+\.rar)(?:\.[^.]+)?$"
        else:
            pattern = re.escape(prefix) + re.escape(separator) + r"\d+(?:\.[^.]+)?$"
            normalizer_pattern = r"^(" + re.escape(prefix) + re.escape(separator) + r"\d+)(?:\.[^.]+)?$"
        for f in os.listdir(root):
            if re.match(pattern, f, re.I):
                old_path = os.path.normpath(os.path.join(root, f))
                if old_path in processed_set:
                    continue

                normalized_name = re.sub(normalizer_pattern, r"\1", f, flags=re.I)
                if new_ext_suffix and normalized_name.lower().endswith(new_ext_suffix.lower()):
                    new_name = normalized_name
                else:
                    new_name = normalized_name if not new_ext_suffix else normalized_name + new_ext_suffix

                new_path = os.path.normpath(os.path.join(root, new_name))
                if not os.path.exists(new_path) or old_path.lower() == new_path.lower():
                    if old_path.lower() != new_path.lower():
                        self.engine.log(f"[PRE-CHECK] 修复分卷: {f} -> {new_name}")
                        try:
                            os.rename(old_path, new_path)
                            processed_set.add(new_path)
                        except Exception as e:
                            self.engine.log(f"[ERROR] 分卷重命名失败: {f} ({e})")
                    else:
                        processed_set.add(old_path)

    def rename_single_file(self, root, source_name, target_name, processed_set):
        old_path = os.path.normpath(os.path.join(root, source_name))
        if old_path in processed_set:
            return

        new_path = os.path.normpath(os.path.join(root, target_name))
        if not os.path.exists(new_path) or old_path.lower() == new_path.lower():
            if old_path.lower() != new_path.lower():
                self.engine.log(f"[PRE-CHECK] 修复后缀: {source_name} -> {target_name}")
                try:
                    os.rename(old_path, new_path)
                    processed_set.add(new_path)
                except Exception as e:
                    self.engine.log(f"[ERROR] 文件重命名失败: {source_name} ({e})")
            else:
                processed_set.add(old_path)

    def execute_rename_plan(self, rename_plan):
        processed_paths = set()
        for instruction in rename_plan:
            if instruction.kind == "series":
                self.rename_series(
                    instruction.root,
                    instruction.prefix,
                    instruction.separator,
                    instruction.new_ext_suffix,
                    processed_paths,
                )
            else:
                self.rename_single_file(
                    instruction.root,
                    instruction.source,
                    instruction.target,
                    processed_paths,
                )

    def pre_check_and_rename(self, target_dir, scene_context=None):
        if not self.directory_may_need_precheck(target_dir):
            return
        self.engine.log(f"\n[PRE-CHECK] 正在检查伪装归档: {os.path.basename(target_dir) or '根目录'}")
        rename_plan = self.build_rename_plan(target_dir, scene_context or self.engine.scene_analyzer.detect_scene_context(target_dir))
        self.execute_rename_plan(rename_plan)
