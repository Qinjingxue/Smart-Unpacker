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

        self.MIN_SIZE = 1 * 1024 * 1024
        self.STRICT_SEMANTIC_SKIP_EXTS = {".dll", ".save", ".py", ".pyc", ".json", ".xml", ".cfg", ".ini", ".sys", ".db", ".msi", ".cur", ".ani", ".ttf", ".woff", ".ico", ".pak", ".obb"}
        self.AMBIGUOUS_RESOURCE_EXTS = {".dat", ".bin"}
        self.LIKELY_RESOURCE_EXTS = self.STRICT_SEMANTIC_SKIP_EXTS | {
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tga",
            ".mp3", ".wav", ".ogg", ".flac", ".aac",
            ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm",
            ".txt", ".log", ".csv", ".pdf",
        }
        self.STANDARD_EXTS = {".7z", ".rar", ".zip", ".gz", ".bz2", ".xz"}
        self.ZIP_CONTAINER_EXTS = {".jar", ".apk", ".ipa", ".epub", ".odt", ".ods", ".odp", ".docx", ".xlsx", ".pptx", ".whl", ".xpi", ".war", ".ear", ".aab"}
        self.ARCHIVE_SCORE_THRESHOLD = 6
        self.MAYBE_ARCHIVE_THRESHOLD = 3
        self.SPLIT_FIRST_PATTERNS = (
            re.compile(r"\.part0*1\.rar(?:\.[^.]+)?$", re.I),
            re.compile(r"\.(7z|zip|rar)\.001(?:\.[^.]+)?$", re.I),
            re.compile(r"\.001(?:\.[^.]+)?$", re.I),
        )
        self.SPLIT_MEMBER_PATTERN = re.compile(r"\.(part\d+\.rar|\d{3})(?:\.[^.]+)?$", re.I)

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
        self.MIN_SIZE = self.app_config.min_inspection_size_bytes
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
        for root, _, files in os.walk(target_dir):
            for filename in files:
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
        for root, filename in self._iter_scan_candidate_files(target_dir):
            if self._should_consider_file_for_nested_scan(root, filename):
                return True
        return False

    def _collect_archive_groups(self, target_dir, scene_context):
        groups = defaultdict(list)
        for root, _, files in os.walk(target_dir):
            root_scene_context = self._resolve_scene_context_for_path(root, target_dir)
            relations = self.relation_builder.build_directory_relationships(root, files, scan_root=target_dir)
            for f in files:
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
        main = next((p for p in paths if re.search(r"\.(part0*1\.rar|7z\.001|zip\.001|7z|zip|rar|gz|bz2|xz)$", p, re.I)), None)
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
            self.log(f"[SCAN] 目录语义识别: {scene_context.scene_type} @ {os.path.basename(target_dir) or '根目录'}")
        self.pre_check_and_rename(target_dir, scene_context)
        return self._scan_directory_target_readonly(target_dir, scene_context=scene_context)

    def _scan_directory_target_readonly(self, target_dir, scene_context=None):
        scene_context = scene_context or self._detect_scene_context(target_dir)

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

    def start(self):
        self.is_running = True
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        start_time = time.time()
        self.reset_scan_caches()
        threading.Thread(target=self.adjust_workers, daemon=True).start()
        executor = ThreadPoolExecutor(max_workers=self.max_workers_limit)
        pending = deque(self.scan_archives())
        futures = {}
        success_count = 0
        try:
            while pending or futures or self.in_progress:
                self._update_pending_task_estimate(len(pending), len(futures))
                while pending and len(futures) < self.max_workers_limit * 2:
                    t = pending.popleft()
                    futures[executor.submit(self.extract, t)] = t
                    self._update_pending_task_estimate(len(pending), len(futures))
                if not futures:
                    time.sleep(0.5)
                    continue
                done, _ = wait(futures.keys(), return_when=FIRST_COMPLETED, timeout=1)
                for f in done:
                    if f in futures:
                        futures.pop(f)
                        try:
                            res = f.result()
                            if res and os.path.exists(res):
                                success_count += 1
                                self.flatten_candidates.add(os.path.normpath(res))
                                if self.should_scan_output_dir(res):
                                    new = self.scan_archives(res)
                                    if new:
                                        pending.extend(new)
                        except Exception:
                            pass
                        finally:
                            self._update_pending_task_estimate(len(pending), len(futures))
            executor.shutdown(wait=True)
            self._cleanup_success_archives()
            flatten_targets = sorted(self.flatten_candidates, key=lambda item: item.count(os.sep))
            if flatten_targets:
                for flatten_target in flatten_targets:
                    if os.path.exists(flatten_target):
                        self.flatten_dirs(flatten_target)
            else:
                self.flatten_dirs(self.root_dir)
            self._log_final_summary(start_time, success_count)
            return RunSummary(success_count=success_count, failed_tasks=list(self.failed_tasks), processed_keys=sorted(self.processed))
        finally:
            self.is_running = False
            self._update_pending_task_estimate(0, 0)
            if self.completion_callback:
                self.completion_callback()


DecompressionEngine = Engine
