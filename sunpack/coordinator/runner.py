import os
import time
from typing import List, Dict, Any

from sunpack.contracts.run_context import RunContext
from sunpack.contracts.results import RunSummary
from sunpack.contracts.tasks import ArchiveTask

from sunpack.rename.scheduler import RenameScheduler

from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.coordinator.space_guard import ExtractionSpaceGuard
from sunpack.coordinator.extraction_batch import ExtractionBatchRunner

from sunpack.postprocess.actions import PostProcessActions
from sunpack.coordinator.reporting import RunReporter

from sunpack.detection import NestedOutputScanPolicy
from sunpack.coordinator.recursion import RecursionController
from sunpack.coordinator.task_scan import ArchiveTaskScanner

class PipelineRunner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        cli_config = config.get("cli") if isinstance(config.get("cli"), dict) else {}
        self.language = "zh" if str(cli_config.get("language") or "").strip().lower() == "zh" else "en"
        self.context = RunContext()
        self.task_scanner = ArchiveTaskScanner(config, self.context)
        self.detector = self.task_scanner.detector
        self.rename_scheduler = RenameScheduler()
        self.logger = RunReporter(language=self.language)
        self.postprocess_actions = PostProcessActions(config, self.context, language=self.language)
        self.space_guard = ExtractionSpaceGuard(self.context, self.postprocess_actions)
        self.disk_monitor = None
        performance_config = config.get("performance", {}) if isinstance(config.get("performance"), dict) else {}
        self.extractor = ExtractionScheduler(
            cli_passwords=config.get("user_passwords", []),
            builtin_passwords=config.get("builtin_passwords", []),
            ensure_space=self.ensure_space,
            max_retries=config.get("max_retries", 3),
            process_config=performance_config,
            output_config=config.get("output", {}),
            extraction_config=config.get("extraction", {}),
        )
        self.output_scan_policy = NestedOutputScanPolicy(config)
        
        recur_cfg = config.get("recursive_extract", {"mode": "fixed", "max_rounds": 1})
        if not isinstance(recur_cfg, dict):
            raise ValueError("recursive_extract must be normalized before PipelineRunner starts")
        recur_mode = recur_cfg.get("mode", "fixed")
        recur_rounds = int(recur_cfg.get("max_rounds", 1))
                
        self.recursion = RecursionController(mode=recur_mode, max_rounds=recur_rounds, language=self.language)
        
        self.batch_runner = ExtractionBatchRunner(
            self.context,
            self.extractor,
            self.output_scan_policy,
            self.rename_scheduler,
            config,
        )

    def text(self, en: str, zh: str) -> str:
        return zh if self.language == "zh" else en

    @property
    def recent_passwords(self) -> list[str]:
        return list(self.extractor.recent_passwords)

    def ensure_space(self, required_gb: int) -> bool:
        return self.space_guard.ensure_space(required_gb)

    def _scan_tasks(self, scan_root: str) -> List[ArchiveTask]:
        return self.task_scanner.scan_root(scan_root)

    def _scan_targets(self, scan_roots: List[str]) -> List[ArchiveTask]:
        return self.task_scanner.scan_targets(scan_roots)

    def _direct_file_tasks(self, file_paths: List[str]) -> List[ArchiveTask]:
        return self.task_scanner.direct_file_tasks(file_paths)

    def _prepare_tasks(self, tasks: List[ArchiveTask]):
        self.batch_runner.prepare_tasks(tasks)

    def _apply_postprocess_actions(self):
        self.postprocess_actions.apply()

    def _execute_tasks(self, tasks: List[ArchiveTask]) -> List[str]:
        return self.batch_runner.execute(tasks)

    def run(self, root_dir: str) -> RunSummary:
        return self.run_targets([root_dir])

    def run_targets(self, target_paths: List[str]) -> RunSummary:
        start_time = time.time()
        first_target = target_paths[0] if target_paths else os.getcwd()
        monitor_root = first_target if os.path.isdir(first_target) else os.path.dirname(first_target)
        self.space_guard.bind_root(monitor_root)
        self.disk_monitor = self.space_guard.disk_monitor
        round_index = 1
        current_roots = list(target_paths)
        prompt_mode = self.recursion.mode == "prompt"
        postprocess_applied = False
        
        while current_roots:
            print(self.text(f"\n[PIPELINE] Starting Round {round_index}", f"\n[PIPELINE] 开始第 {round_index} 轮"))
            new_roots = self._execute_tasks(self._scan_targets(current_roots))

            if prompt_mode:
                self._apply_postprocess_actions()
                postprocess_applied = True

            # Check recursion
            if not self.recursion.should_continue(round_index, bool(new_roots)):
                break
            if prompt_mode and not self.recursion.prompt_continue(round_index):
                break
                
            current_roots = new_roots
            round_index += 1

        if not postprocess_applied:
            self._apply_postprocess_actions()

        log_dir = first_target if os.path.isdir(first_target) else os.path.dirname(first_target)
        self.logger.log_final_summary(
            log_dir,
            start_time,
            self.context.success_count,
            self.context.failed_tasks,
            recovered_outputs=self.context.recovered_outputs,
        )
        self.extractor.close()
        
        return RunSummary(
            success_count=self.context.success_count,
            failed_tasks=self.context.failed_tasks,
            processed_keys=list(self.context.processed_keys),
            partial_success_count=self.context.partial_success_count,
            recovered_outputs=list(self.context.recovered_outputs),
        )

    def run_direct_files(self, file_paths: List[str]) -> RunSummary:
        start_time = time.time()
        first_target = file_paths[0] if file_paths else os.getcwd()
        monitor_root = os.path.dirname(first_target) if os.path.isfile(first_target) else os.getcwd()
        self.space_guard.bind_root(monitor_root)
        self.disk_monitor = self.space_guard.disk_monitor

        print(self.text("\n[PIPELINE] Starting direct file extraction", "\n[PIPELINE] 开始直接文件解压"))
        self._execute_tasks(self._direct_file_tasks(file_paths))
        self._apply_postprocess_actions()

        self.logger.log_final_summary(
            monitor_root,
            start_time,
            self.context.success_count,
            self.context.failed_tasks,
            recovered_outputs=self.context.recovered_outputs,
        )
        self.extractor.close()

        return RunSummary(
            success_count=self.context.success_count,
            failed_tasks=self.context.failed_tasks,
            processed_keys=list(self.context.processed_keys),
            partial_success_count=self.context.partial_success_count,
            recovered_outputs=list(self.context.recovered_outputs),
        )
