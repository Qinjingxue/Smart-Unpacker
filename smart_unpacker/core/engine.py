from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from smart_unpacker.core.cleanup import CleanupManager
from smart_unpacker.core.extraction import Extractor
from smart_unpacker.core.scheduler import WorkerScheduler
from smart_unpacker.detection.inspector import ArchiveInspector
from smart_unpacker.detection.rename_planner import RenamePlanner
from smart_unpacker.detection.scene_rules import SceneAnalyzer
from smart_unpacker.detection.split_relations import RelationBuilder
from smart_unpacker.support.logging import CallbackLogger
from smart_unpacker.support.resources import ResourceLocator
from smart_unpacker.support.types import ArchiveTask, GroupDecision, RunSummary


class Engine:
    def __init__(self, root_dir, passwords, log_callback, completion_callback, selected_paths=None, use_builtin_passwords=True):
        self.root_dir = os.path.normpath(root_dir)
        self.user_passwords = passwords or []
        self.recent_passwords = []
        self.builtin_passwords = ResourceLocator().get_builtin_passwords() if use_builtin_passwords else []
        self.logger = CallbackLogger(log_callback)
        self.completion_callback = completion_callback
        self.selected_paths = [os.path.normpath(path) for path in (selected_paths or []) if path]

        self.is_running = False
        self.failed_tasks = []
        self.unpacked_archives = deque()
        self.processed = set()
        self.in_progress = set()
        self.flatten_candidates = set()
        self.lock = threading.Lock()

        self.io_history = deque(maxlen=8)
        self.max_retries = 3
        self.min_workers = 1
        self.max_workers_limit = 1
        self.dynamic_floor_workers = 1
        self.active_workers = 0
        self.current_concurrency_limit = 1
        self.pending_task_estimate = 0
        self.scale_up_streak = 0
        self.scale_down_streak = 0
        self.concurrency_cond = threading.Condition(self.lock)

        self.resource_locator = ResourceLocator()
        self.app_config = self.resource_locator.get_app_config()
        detection_config = self.app_config.detection
        self.MIN_SIZE = self.app_config.min_inspection_size_bytes
        self.STRICT_SEMANTIC_SKIP_EXTS = set(detection_config.strict_semantic_skip_exts)
        self.AMBIGUOUS_RESOURCE_EXTS = set(detection_config.ambiguous_resource_exts)
        self.LIKELY_RESOURCE_EXTS = self.STRICT_SEMANTIC_SKIP_EXTS | set(detection_config.likely_resource_exts_extra)
        self.STANDARD_EXTS = set(detection_config.standard_archive_exts)
        self.ARCHIVE_SCORE_THRESHOLD = detection_config.archive_score_threshold
        self.MAYBE_ARCHIVE_THRESHOLD = detection_config.maybe_archive_threshold
        self.SPLIT_FIRST_PATTERNS = tuple(re.compile(pattern, re.I) for pattern in detection_config.split_first_patterns)
        self.SPLIT_MEMBER_PATTERN = re.compile(detection_config.split_member_pattern, re.I)
        self.DISGUISED_ARCHIVE_NAME_PATTERNS = tuple(
            re.compile(pattern, re.I) for pattern in detection_config.disguised_archive_name_patterns
        )
        self.BLACKLIST_DIR_PATTERNS = tuple(
            re.compile(pattern, re.I) for pattern in detection_config.blacklist.directory_patterns
        )
        self.BLACKLIST_FILE_PATTERNS = tuple(
            re.compile(pattern, re.I) for pattern in detection_config.blacklist.filename_patterns
        )
        self._blacklist_logged_paths = set()
        self.max_workers_limit = max(1, self.app_config.max_workers_override or self.detect_max_workers())
        medium_floor = max(1, self.app_config.scheduler_medium_floor_workers)
        self.dynamic_floor_workers = min(medium_floor, self.max_workers_limit)
        if self.app_config.initial_concurrency_limit > 0:
            self.current_concurrency_limit = min(self.app_config.initial_concurrency_limit, self.max_workers_limit)
        else:
            self.current_concurrency_limit = min(4, self.max_workers_limit) if self.max_workers_limit > 1 else 1
        self.seven_z_path = self.resource_locator.find_seven_zip_path()
        self.scene_analyzer = SceneAnalyzer(self)
        self.relation_builder = RelationBuilder(self)
        self.inspector = ArchiveInspector(self)
        self.rename_planner = RenamePlanner(self)
        self.cleanup_manager = CleanupManager(self)
        self.extractor = Extractor(self)
        self.scheduler = WorkerScheduler(self)

        self.inspect_cache = self.inspector.inspect_cache
        self.validation_cache = self.inspector.validation_cache
        self.probe_cache = self.inspector.probe_cache
        self.scene_context_cache = self.scene_analyzer.scene_context_cache

    def detect_max_workers(self):
        cpu_count = os.cpu_count() or 4
        try:
            cmd = 'powershell -Command "Get-PhysicalDisk | Select-Object -Property MediaType"'
            res = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            if "SSD" in res.stdout.upper():
                return max(2, cpu_count)
        except Exception:
            pass
        return 2

    def log(self, message):
        self.logger.log(message)

    def _safe_relpath(self, path, start):
        try:
            rel = os.path.relpath(path, start)
        except ValueError:
            return None
        if rel.startswith(".."):
            return None
        return rel

    def _windows_relpath(self, path, start):
        rel = self._safe_relpath(os.path.normpath(path), os.path.normpath(start))
        if rel is None:
            return None
        if rel == ".":
            return ""
        return rel.replace("/", "\\").replace(os.sep, "\\")

    def _slash_relpath(self, path, start):
        windows_rel = self._windows_relpath(path, start)
        return None if windows_rel is None else windows_rel.replace("\\", "/")

    def _blacklist_path_candidates(self, path, scan_root, *, include_basename=True):
        candidates = []
        if include_basename:
            basename = os.path.basename(os.path.normpath(path))
            if basename:
                candidates.append(basename)
        windows_rel = self._windows_relpath(path, scan_root)
        if windows_rel:
            candidates.append(windows_rel)
            slash_rel = windows_rel.replace("\\", "/")
            if slash_rel != windows_rel:
                candidates.append(slash_rel)
        return candidates

    def _matches_any_blacklist_pattern(self, patterns, candidates):
        return any(pattern.search(candidate) for pattern in patterns for candidate in candidates if candidate)

    def _log_blacklist_skip_once(self, category, path, scan_root=None):
        rel = self._windows_relpath(path, scan_root) if scan_root else None
        label = rel or os.path.basename(path) or path
        key = (category, os.path.normcase(os.path.normpath(path)))
        if key in self._blacklist_logged_paths:
            return
        self._blacklist_logged_paths.add(key)
        if category == "dir":
            self.log(f"[SCAN] 黑名单目录跳过: {label}")
        elif category == "precheck_file":
            self.log(f"[PRE-CHECK] 黑名单文件跳过重命名: {label}")
        else:
            self.log(f"[SCAN] 黑名单文件跳过: {label}")

    def matches_blacklisted_dir(self, path, scan_root):
        if not self.BLACKLIST_DIR_PATTERNS:
            return False
        candidates = self._blacklist_path_candidates(path, scan_root)
        if not candidates:
            return False
        return self._matches_any_blacklist_pattern(self.BLACKLIST_DIR_PATTERNS, candidates)

    def matches_blacklisted_file(self, path, scan_root):
        if not self.BLACKLIST_FILE_PATTERNS:
            return False
        candidates = self._blacklist_path_candidates(path, scan_root)
        if not candidates:
            return False
        return self._matches_any_blacklist_pattern(self.BLACKLIST_FILE_PATTERNS, candidates)

    def _walk_unignored(self, target_dir, scan_root=None):
        scan_root = os.path.normpath(scan_root or target_dir)
        for root, dirs, files in os.walk(target_dir, topdown=True):
            if self.matches_blacklisted_dir(root, scan_root):
                self._log_blacklist_skip_once("dir", root, scan_root)
                dirs[:] = []
                continue

            kept_dirs = []
            for dirname in dirs:
                dir_path = os.path.join(root, dirname)
                if self.matches_blacklisted_dir(dir_path, scan_root):
                    self._log_blacklist_skip_once("dir", dir_path, scan_root)
                    continue
                kept_dirs.append(dirname)
            dirs[:] = kept_dirs
            yield root, dirs, files

    def get_resource_base_path(self):
        return self.resource_locator.get_resource_base_path()

    def get_resource_path(self, *relative_parts):
        return self.resource_locator.get_resource_path(*relative_parts)

    def find_seven_zip_path(self):
        return self.resource_locator.find_seven_zip_path()

    def _detect_scene_context(self, target_dir):
        return self.scene_analyzer.detect_scene_context(target_dir)

    def _resolve_scene_context_for_path(self, current_dir, scan_root):
        return self.scene_analyzer.resolve_scene_context_for_path(current_dir, scan_root)

    def _probe_archive_with_7z(self, path):
        return self.inspector._probe_archive_with_7z(path)

    def _validate_with_7z(self, path):
        return self.inspector._validate_with_7z(path)

    def inspect_archive_candidate(self, path, relation=None, scene_context=None):
        return self.inspector.inspect_archive_candidate(path, relation=relation, scene_context=scene_context)

    def is_possible_archive(self, path):
        return self.inspect_archive_candidate(path).should_extract

    def pre_check_and_rename(self, target_dir, scene_context=None):
        self.rename_planner.pre_check_and_rename(target_dir, scene_context)

    def get_logical_name(self, filename: str, is_archive: bool = False) -> str:
        return self.relation_builder.get_logical_name(filename, is_archive=is_archive)

    def _detect_filename_split_role(self, filename):
        return self.relation_builder.detect_filename_split_role(filename)

    def _build_file_relation(self, root, filename, filenames, scan_root=None):
        return self.relation_builder.build_file_relation(root, filename, filenames, scan_root=scan_root)

    def _build_directory_relationships(self, root, files, scan_root=None):
        return self.relation_builder.build_directory_relationships(root, files, scan_root=scan_root)

    def reset_scan_caches(self):
        self.inspector.clear_caches()
        self.scene_analyzer.clear_caches()

    def _looks_like_disguised_archive_name(self, filename):
        return self.inspector._looks_like_disguised_archive_name(filename)

    def _iter_scan_candidate_files(self, target_dir):
        for root, _, files in self._walk_unignored(target_dir):
            for filename in files:
                path = os.path.join(root, filename)
                if self.matches_blacklisted_file(path, target_dir):
                    self._log_blacklist_skip_once("file", path, target_dir)
                    continue
                yield root, filename

    def _should_consider_file_for_nested_scan(self, root, filename):
        lower_name = filename.lower()
        _, ext = os.path.splitext(lower_name)
        if ext in self.STANDARD_EXTS or ext == ".exe":
            return True
        if ext in self.inspector.CARRIER_EXTS:
            file_path = os.path.join(root, filename)
            try:
                return os.path.getsize(file_path) >= self.MIN_SIZE
            except OSError:
                return False
        if ext in self.AMBIGUOUS_RESOURCE_EXTS:
            return self._looks_like_disguised_archive_name(lower_name)
        if self._detect_filename_split_role(lower_name) is not None:
            return True
        if self._looks_like_disguised_archive_name(lower_name):
            return True
        if not ext:
            file_path = os.path.join(root, filename)
            try:
                return os.path.getsize(file_path) >= self.MIN_SIZE * 2
            except OSError:
                return False
        return False

    def should_scan_output_dir(self, target_dir):
        scene_context = self._detect_scene_context(target_dir)
        if scene_context.scene_type != "generic" and scene_context.match_strength == "strong":
            self.log(
                f"[SCAN] 跳过强场景目录: {scene_context.scene_type} @ {os.path.basename(target_dir) or '根目录'}"
            )
            return False
        for root, filename in self._iter_scan_candidate_files(target_dir):
            if self._should_consider_file_for_nested_scan(root, filename):
                return True
        return False

    def _collect_archive_groups(self, target_dir, scene_context):
        groups = defaultdict(list)
        for root, _, files in self._walk_unignored(target_dir):
            allowed_files = []
            for filename in files:
                path = os.path.join(root, filename)
                if self.matches_blacklisted_file(path, target_dir):
                    self._log_blacklist_skip_once("file", path, target_dir)
                    continue
                allowed_files.append(filename)
            root_scene_context = self._resolve_scene_context_for_path(root, target_dir)
            relations = self.relation_builder.build_directory_relationships(root, allowed_files, scan_root=target_dir)
            for f in allowed_files:
                relation = relations[f]
                path = relation.path
                info = self.inspect_archive_candidate(path, relation=relation, scene_context=root_scene_context)
                if self._is_group_candidate(info, relation):
                    lname = self.get_logical_name(f, is_archive=info.should_extract).lower()
                    key = os.path.normpath(os.path.join(root, lname))
                    groups[key].append(path)
        return groups

    def _is_group_candidate(self, info, relation):
        return info.should_extract or info.decision == "maybe_archive" or relation.is_split_related

    def _select_group_main_archive(self, paths):
        main = next((p for p in paths if self._detect_filename_split_role(p) == "first"), None)
        if main:
            return main
        main = next((p for p in paths if os.path.splitext(p.lower())[1] in self.STANDARD_EXTS), None)
        if main:
            return main
        exe_main = next((p for p in paths if p.lower().endswith(".exe")), None)
        if exe_main:
            return exe_main
        return next((p for p in paths if not p.lower().endswith(".exe")), None)

    def _build_archive_task(self, key, paths):
        inspections = [self.inspect_archive_candidate(p) for p in paths]
        extractables = [item for item in inspections if item.should_extract]
        maybes = [item for item in inspections if item.decision == "maybe_archive"]
        if not extractables and not maybes:
            return None

        main = self._select_group_main_archive(paths)
        if not main:
            return None

        main_info = self.inspect_archive_candidate(main)
        group_score = max((item.score for item in inspections), default=0)
        has_strong_signal = any(item.magic_matched or item.probe_detected_archive for item in inspections)
        group_should_extract = (
            bool(extractables)
            or (group_score >= self.ARCHIVE_SCORE_THRESHOLD and len(paths) > 1 and has_strong_signal)
            or (
                len(paths) == 1
                and main_info.decision == "maybe_archive"
                and (
                    main_info.magic_matched
                    or main_info.probe_detected_archive
                    or main_info.ext in self.STANDARD_EXTS
                )
            )
        )
        if not group_should_extract:
            self.log(f"[SCAN] 跳过低置信度候选: {os.path.basename(main)} | 分数={main_info.score} | 判定={main_info.decision}")
            return None

        group_info = GroupDecision(
            group_score=group_score,
            group_should_extract=group_should_extract,
            main_info=main_info,
            inspections=inspections,
            reasons=[],
        )
        if group_should_extract and not main_info.should_extract and len(paths) > 1:
            group_info.reasons.append(f"分卷组整体分数={group_score}")

        return ArchiveTask(key=key, main_path=main, all_parts=paths, group_info=group_info)

    def _scan_directory_target(self, target_dir):
        scene_context = self._detect_scene_context(target_dir)
        if scene_context.scene_type != "generic":
            self.log(
                f"[SCAN] 目录语义识别: {scene_context.scene_type} ({scene_context.match_strength}) @ "
                f"{os.path.basename(target_dir) or '根目录'}"
            )
        self.pre_check_and_rename(target_dir, scene_context)
        return self._scan_directory_target_readonly(target_dir, scene_context=scene_context)

    def _scan_directory_target_readonly(self, target_dir, scene_context=None):
        scene_context = scene_context or self._detect_scene_context(target_dir)
        if scene_context.scene_type != "generic" and scene_context.match_strength == "strong":
            self.log(
                f"[SCAN] 强场景目录已整目录跳过: {scene_context.scene_type} @ {os.path.basename(target_dir) or '根目录'}"
            )
            return []

        groups = self._collect_archive_groups(target_dir, scene_context)
        archives = []
        for key, paths in groups.items():
            with self.lock:
                if key in self.processed or key in self.in_progress:
                    continue
                paths.sort()
                task = self._build_archive_task(key, paths)
                if task:
                    archives.append(task)
        return archives

    def _add_unique_tasks(self, target_list, seen_keys, tasks):
        for task in tasks:
            key = task.key
            if key in seen_keys:
                continue
            seen_keys.add(key)
            target_list.append(task)

    def _scan_selected_targets(self):
        archives = []
        seen_keys = set()
        selected_dirs = []
        selected_files = []

        for path in self.selected_paths:
            if os.path.isdir(path):
                selected_dirs.append(path)
            elif os.path.isfile(path):
                selected_files.append(path)

        for directory in selected_dirs:
            self._add_unique_tasks(archives, seen_keys, self._scan_directory_target(directory))

        parent_cache = {}
        for file_path in selected_files:
            if any(self._safe_relpath(file_path, directory) is not None for directory in selected_dirs):
                continue

            parent_dir = os.path.dirname(file_path)
            if parent_dir not in parent_cache:
                parent_cache[parent_dir] = self._scan_directory_target(parent_dir)

            expected_key = self.get_logical_name(os.path.basename(file_path), is_archive=True).lower()
            matched_tasks = [task for task in parent_cache[parent_dir] if os.path.basename(task.key).lower() == expected_key]

            if not matched_tasks:
                normalized_file = os.path.normcase(file_path)
                matched_tasks = [task for task in parent_cache[parent_dir] if os.path.normcase(task.main_path) == normalized_file]

            self._add_unique_tasks(archives, seen_keys, matched_tasks)
        return archives

    def _scan_selected_targets_readonly(self):
        archives = []
        seen_keys = set()
        selected_dirs = []
        selected_files = []

        for path in self.selected_paths:
            if os.path.isdir(path):
                selected_dirs.append(path)
            elif os.path.isfile(path):
                selected_files.append(path)

        for directory in selected_dirs:
            self._add_unique_tasks(archives, seen_keys, self._scan_directory_target_readonly(directory))

        parent_cache = {}
        for file_path in selected_files:
            if any(self._safe_relpath(file_path, directory) is not None for directory in selected_dirs):
                continue

            parent_dir = os.path.dirname(file_path)
            if parent_dir not in parent_cache:
                parent_cache[parent_dir] = self._scan_directory_target_readonly(parent_dir)

            expected_key = self.get_logical_name(os.path.basename(file_path), is_archive=True).lower()
            matched_tasks = [task for task in parent_cache[parent_dir] if os.path.basename(task.key).lower() == expected_key]

            if not matched_tasks:
                normalized_file = os.path.normcase(file_path)
                matched_tasks = [task for task in parent_cache[parent_dir] if os.path.normcase(task.main_path) == normalized_file]

            self._add_unique_tasks(archives, seen_keys, matched_tasks)
        return archives

    def scan_archives(self, target_dir=None):
        if target_dir is not None:
            return self._scan_directory_target(target_dir)
        if self.selected_paths:
            return self._scan_selected_targets()
        return self._scan_directory_target(self.root_dir)

    def scan_archives_readonly(self, target_dir=None):
        if target_dir is not None:
            return self._scan_directory_target_readonly(target_dir)
        if self.selected_paths:
            return self._scan_selected_targets_readonly()
        return self._scan_directory_target_readonly(self.root_dir)

    def adjust_workers(self):
        self.scheduler.adjust_workers()

    def _update_pending_task_estimate(self, pending_count, futures_count):
        self.scheduler.update_pending_task_estimate(pending_count, futures_count)

    def ensure_space(self, required_gb=5):
        return self.cleanup_manager.ensure_space(required_gb)

    def _make_startupinfo(self):
        si = subprocess.STARTUPINFO() if os.name == "nt" else None
        if si:
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return si

    @property
    def passwords(self):
        return self.get_passwords_to_try()

    def get_passwords_to_try(self):
        from smart_unpacker.support.passwords import dedupe_passwords
        combined = self.user_passwords + self.recent_passwords + self.builtin_passwords
        return dedupe_passwords(combined)

    def add_recent_password(self, password):
        if not password:
            return
        with self.lock:
            if password in self.recent_passwords:
                self.recent_passwords.remove(password)
            self.recent_passwords.insert(0, password)

    def _has_definite_wrong_password(self, err_text):
        return self.extractor.has_definite_wrong_password(err_text)

    def _has_archive_damage_signals(self, err_text):
        return self.extractor.has_archive_damage_signals(err_text)

    def _find_working_password(self, archive, startupinfo):
        return self.extractor.find_working_password(archive, startupinfo)

    def _extract_archive_once(self, archive, out_dir, password, startupinfo):
        return self.extractor.extract_archive_once(archive, out_dir, password, startupinfo)

    def _classify_extract_error(self, run_result, err_text, archive=None, all_parts=None):
        return self.extractor.classify_extract_error(run_result, err_text, archive=archive, all_parts=all_parts)

    def _cleanup_failed_output(self, out_dir):
        self.cleanup_manager.cleanup_failed_output(out_dir)

    def _cleanup_success_archives(self):
        self.cleanup_manager.cleanup_success_archives()

    def _log_final_summary(self, start_time, success_count):
        self.cleanup_manager.log_final_summary(start_time, success_count)

    def extract(self, task):
        return self.extractor.extract(task)

    def flatten_dirs(self, base):
        self.cleanup_manager.flatten_dirs(base)

    def _apply_post_extract_actions(self):
        self._cleanup_success_archives()
        if self.app_config.post_extract.flatten_single_directory:
            flatten_targets = sorted(self.flatten_candidates, key=lambda item: item.count(os.sep))
            if flatten_targets:
                for flatten_target in flatten_targets:
                    if os.path.exists(flatten_target):
                        self.flatten_dirs(flatten_target)
            else:
                self.flatten_dirs(self.root_dir)
        self.flatten_candidates.clear()
        self.reset_scan_caches()

    def _prompt_continue_recursive_extract(self, round_index):
        while True:
            try:
                answer = input(f"[CLI] 第 {round_index} 轮解压完成。是否继续下一轮递归解压？(y/n): ")
            except EOFError:
                self.log("[CLI] 未读取到输入，停止递归解压。")
                return False
            except KeyboardInterrupt:
                self.log("[CLI] 用户取消，停止递归解压。")
                return False
            normalized = answer.strip().lower()
            if normalized in {"y", "yes"}:
                return True
            if normalized in {"n", "no", ""}:
                return False
            print("请输入 y 或 n。", flush=True)

    def _scan_next_round_targets(self, scan_roots):
        tasks = []
        seen_keys = set()
        for scan_root in scan_roots:
            if os.path.exists(scan_root):
                self._add_unique_tasks(tasks, seen_keys, self.scan_archives(scan_root))
        return deque(tasks)

    def _run_task_round(self, executor, pending):
        futures = {}
        round_success_count = 0
        next_scan_roots = []
        while pending or futures or self.in_progress:
            self._update_pending_task_estimate(len(pending), len(futures))
            while pending and len(futures) < self.max_workers_limit * 2:
                task = pending.popleft()
                futures[executor.submit(self.extract, task)] = task
                self._update_pending_task_estimate(len(pending), len(futures))
            if not futures:
                time.sleep(0.5)
                continue
            done, _ = wait(futures.keys(), return_when=FIRST_COMPLETED, timeout=1)
            for future in done:
                if future not in futures:
                    continue
                futures.pop(future)
                try:
                    result_path = future.result()
                    if result_path and os.path.exists(result_path):
                        round_success_count += 1
                        self.flatten_candidates.add(os.path.normpath(result_path))
                        self.reset_scan_caches()
                        if self.should_scan_output_dir(result_path):
                            next_scan_roots.append(result_path)
                except Exception:
                    pass
                finally:
                    self._update_pending_task_estimate(len(pending), len(futures))
        return round_success_count, next_scan_roots

    def _should_stop_after_round(self, round_index):
        recursion = self.app_config.recursive_extract
        return recursion.mode == "fixed" and round_index >= recursion.max_rounds

    def start(self):
        self.is_running = True
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        start_time = time.time()
        self.reset_scan_caches()
        threading.Thread(target=self.adjust_workers, daemon=True).start()
        executor = ThreadPoolExecutor(max_workers=self.max_workers_limit)
        pending = deque(self.scan_archives())
        success_count = 0
        round_index = 1
        prompt_mode = self.app_config.recursive_extract.mode == "prompt"
        post_extract_applied = False
        try:
            while pending:
                self.log(f"\n[SCAN] 开始第 {round_index} 轮递归解压扫描。")
                round_success_count, next_scan_roots = self._run_task_round(executor, pending)
                success_count += round_success_count

                if prompt_mode:
                    self._apply_post_extract_actions()
                    post_extract_applied = True

                if self._should_stop_after_round(round_index) or not next_scan_roots:
                    break
                if prompt_mode and not self._prompt_continue_recursive_extract(round_index):
                    break

                round_index += 1
                pending = self._scan_next_round_targets(next_scan_roots)
            executor.shutdown(wait=True)
            if not post_extract_applied:
                self._apply_post_extract_actions()
            self._log_final_summary(start_time, success_count)
            return RunSummary(success_count=success_count, failed_tasks=list(self.failed_tasks), processed_keys=sorted(self.processed))
        finally:
            self.is_running = False
            self._update_pending_task_estimate(0, 0)
            if self.completion_callback:
                self.completion_callback()


DecompressionEngine = Engine
