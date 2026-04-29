import os
import shutil
import subprocess
from typing import Any, Callable, Optional

from packrelic.contracts.tasks import ArchiveTask, SplitArchiveInfo
from packrelic.extraction.internal.workflow.errors import classify_extract_error
from packrelic.extraction.internal.workflow.retry_policy import ExtractRetryPolicy
from packrelic.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from packrelic.extraction.internal.workflow.split_entry import SplitEntryResolver
from packrelic.extraction.progress import has_recoverable_partial_outputs, write_extraction_progress_manifest_payload
from packrelic.extraction.result import ExtractionResult
from packrelic.passwords.result import PasswordResolution


class SingleArchiveExtractor:
    def __init__(
        self,
        seven_z_path: str,
        password_store,
        password_resolver,
        metadata_scanner,
        rename_scheduler,
        ensure_space: Callable[[int], bool],
        retry_policy: ExtractRetryPolicy,
        split_entry_resolver: SplitEntryResolver,
        sevenzip_runner: SevenZipRunner,
        best_effort: bool = True,
    ):
        self.seven_z_path = seven_z_path
        self.password_store = password_store
        self.password_resolver = password_resolver
        self.metadata_scanner = metadata_scanner
        self.rename_scheduler = rename_scheduler
        self.ensure_space = ensure_space
        self.retry_policy = retry_policy
        self.split_entry_resolver = split_entry_resolver
        self.sevenzip_runner = sevenzip_runner
        self.best_effort = bool(best_effort)

    def extract(
        self,
        task: ArchiveTask,
        out_dir: str,
        split_info: Optional[SplitArchiveInfo] = None,
        runtime_scheduler: Any = None,
    ) -> ExtractionResult:
        archive = task.main_path
        split_info = split_info or task.split_info
        archive, all_parts, split_info = self.split_entry_resolver.resolve(
            archive,
            list(task.all_parts or [archive]),
            split_info,
        )
        is_split = split_info.is_split or len(all_parts) > 1

        print(f"\n[EXTRACT] 开始: {archive}")

        if not self.ensure_space(5):
            return self._failed(
                archive,
                out_dir,
                all_parts,
                "磁盘空间不足",
                diagnostics={"failure_stage": "preflight", "failure_kind": "disk_space"},
            )

        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as exc:
            return self._failed(
                archive,
                out_dir,
                all_parts,
                f"目录创建失败: {exc}",
                diagnostics={"failure_stage": "preflight", "failure_kind": "output_filesystem", "message": str(exc)},
            )

        startupinfo = self._startupinfo()
        retry_count = 0
        while retry_count < self.retry_policy.max_retries:
            if not self.ensure_space(5):
                shutil.rmtree(out_dir, ignore_errors=True)
                return self._failed(
                    archive,
                    out_dir,
                    all_parts,
                    "磁盘空间不足",
                    diagnostics={"failure_stage": "preflight", "failure_kind": "disk_space"},
                )
            try:
                os.makedirs(out_dir, exist_ok=True)
            except Exception as exc:
                return self._failed(
                    archive,
                    out_dir,
                    all_parts,
                    f"目录创建失败: {exc}",
                    diagnostics={"failure_stage": "preflight", "failure_kind": "output_filesystem", "message": str(exc)},
                )

            staged = self.rename_scheduler.normalize_archive_paths(
                archive,
                all_parts,
                startupinfo=startupinfo,
                volume_entries=list(split_info.volumes or []),
            )
            run_archive = staged.archive
            run_parts = staged.run_parts
            cleanup_parts = staged.cleanup_parts
            run_result = None
            test_result = None
            err = ""
            correct_pwd = None
            selected_codepage = None

            try:
                resolution = self._resolve_password(task, run_archive, run_parts)
                correct_pwd = resolution.password
                test_result = resolution.test_result
                test_err = resolution.error_text
                if self.password_store.has_candidates():
                    if correct_pwd is None and "wrong password" in test_err:
                        if is_split:
                            correct_pwd = ""
                        else:
                            shutil.rmtree(out_dir, ignore_errors=True)
                            return self._failed(
                                archive,
                                out_dir,
                                run_parts,
                                "密码错误或未知密码",
                                diagnostics=self._diagnostics_from(test_result),
                            )

                selected_codepage = self._codepage_from_facts(task)

                if correct_pwd is None:
                    err = test_err
                else:
                    run_result = self.sevenzip_runner.run_extract(
                        archive_path=run_archive,
                        part_paths=run_parts,
                        out_dir=out_dir,
                        password=correct_pwd,
                        selected_codepage=selected_codepage,
                        startupinfo=startupinfo,
                        runtime_scheduler=runtime_scheduler,
                        task=task,
                    )

                    if run_result.returncode == 0:
                        diagnostics = self._diagnostics_from(run_result)
                        if self._empty_repaired_success(diagnostics, task):
                            print(f"[EXTRACT] 失败: {archive} (错误: 修复结果没有可提取文件)")
                            shutil.rmtree(out_dir, ignore_errors=True)
                            diagnostics["failure_stage"] = "verification"
                            diagnostics["failure_kind"] = "empty_repair_output"
                            return self._failed(
                                archive,
                                out_dir,
                                run_parts,
                                "修复结果没有可提取文件",
                                password_used=correct_pwd,
                                selected_codepage=selected_codepage,
                                diagnostics=diagnostics,
                            )
                        print(f"[EXTRACT] 成功: {archive}")
                        manifest_path = ""
                        manifest_payload = None
                        if diagnostics.get("result"):
                            manifest_path, manifest_payload = write_extraction_progress_manifest_payload(
                                archive=archive,
                                out_dir=out_dir,
                                diagnostics=diagnostics,
                                round_index=retry_count + 1,
                            )
                            diagnostics["progress_manifest"] = manifest_path
                        return ExtractionResult(
                            success=True,
                            archive=archive,
                            out_dir=out_dir,
                            all_parts=cleanup_parts,
                            password_used=correct_pwd,
                            selected_codepage=selected_codepage,
                            diagnostics=diagnostics,
                            progress_manifest=manifest_path,
                            progress_manifest_payload=manifest_payload,
                        )

                    err = f"{run_result.stdout}\n{run_result.stderr}".lower()
            finally:
                self.rename_scheduler.cleanup_normalized_split_group(staged)

            if self.retry_policy.can_retry(run_result, err, retry_count, archive, is_split):
                retry_count += 1
                if self.retry_policy.needs_space_recheck(run_result, err) and not self.ensure_space(10):
                    shutil.rmtree(out_dir, ignore_errors=True)
                    return self._failed(
                        archive,
                        out_dir,
                        all_parts,
                        "磁盘空间不足",
                        diagnostics={"failure_stage": "retry_preflight", "failure_kind": "disk_space"},
                    )
                shutil.rmtree(out_dir, ignore_errors=True)
                print(f"[EXTRACT] 临时失败，准备第 {retry_count + 1}/{self.retry_policy.max_retries} 次尝试: {archive}")
                self.retry_policy.backoff(retry_count)
                continue

            error_msg = classify_extract_error(run_result or test_result, err, archive=archive, is_split_archive=is_split)
            error_msg = self.retry_policy.append_retry_count(error_msg, retry_count)
            print(f"[EXTRACT] 失败: {archive} (错误: {error_msg})")
            diagnostics = self._diagnostics_from(run_result or test_result)
            if self.best_effort and has_recoverable_partial_outputs(diagnostics, out_dir):
                manifest_path, manifest_payload = write_extraction_progress_manifest_payload(
                    archive=archive,
                    out_dir=out_dir,
                    diagnostics=diagnostics,
                    round_index=retry_count + 1,
                )
                diagnostics["partial_outputs"] = True
                diagnostics["progress_manifest"] = manifest_path
                return self._failed(
                    archive,
                    out_dir,
                    run_parts,
                    error_msg,
                    password_used=correct_pwd,
                    selected_codepage=selected_codepage,
                    diagnostics=diagnostics,
                    partial_outputs=True,
                    progress_manifest=manifest_path,
                    progress_manifest_payload=manifest_payload,
                )
            shutil.rmtree(out_dir, ignore_errors=True)
            return self._failed(
                archive,
                out_dir,
                run_parts,
                error_msg,
                password_used=correct_pwd,
                selected_codepage=selected_codepage,
                diagnostics=diagnostics,
            )

        shutil.rmtree(out_dir, ignore_errors=True)
        return self._failed(
            archive,
            out_dir,
            all_parts,
            "磁盘空间不足",
            diagnostics={"failure_stage": "retry_exhausted", "failure_kind": "unknown"},
        )

    def _resolve_password(self, task: ArchiveTask, archive_path: str, part_paths: list[str]):
        fact_bag = getattr(task, "fact_bag", None)
        known_password = fact_bag.get("archive.password") if fact_bag is not None and hasattr(fact_bag, "get") else None
        if known_password is not None:
            return PasswordResolution(password=str(known_password), archive_key=task.key)
        archive_state = task.archive_state() if hasattr(task, "archive_state") else None
        if archive_state is not None and archive_state.patches:
            if not self._facts_require_password(fact_bag):
                return PasswordResolution(password="", archive_key=task.key, encrypted=False)
            return PasswordResolution(
                password=None,
                archive_key=task.key,
                encrypted=True,
                error_text="password verification is unsupported for patched archive state without a resolved password",
            )
        if not self.password_store.has_candidates() and not self._facts_require_password(fact_bag):
            return PasswordResolution(password="", archive_key=task.key, encrypted=False)
        password_tester = self.password_resolver.password_tester
        if not password_tester.passwords:
            return PasswordResolution(password="", archive_key=task.key, encrypted=False)
        return self.password_resolver.resolve(
            archive_path,
            task.fact_bag,
            part_paths=part_paths,
            archive_key=task.key,
        )

    @staticmethod
    def _codepage_from_facts(task: ArchiveTask) -> str | None:
        fact_bag = getattr(task, "fact_bag", None)
        if fact_bag is None or not hasattr(fact_bag, "get"):
            return None
        metadata = fact_bag.get("archive.metadata") or {}
        if isinstance(metadata, dict) and metadata.get("selected_codepage"):
            return str(metadata.get("selected_codepage"))
        return None

    @staticmethod
    def _facts_require_password(fact_bag) -> bool:
        if fact_bag is None or not hasattr(fact_bag, "get"):
            return False
        health = fact_bag.get("resource.health") or {}
        if isinstance(health, dict) and (health.get("is_encrypted") or health.get("is_wrong_password")):
            return True
        return False

    def _startupinfo(self):
        import sys

        if sys.platform != "win32":
            return None
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return startupinfo

    def _failed(
        self,
        archive: str,
        out_dir: str,
        all_parts: list[str],
        error: str,
        *,
        password_used: str | None = None,
        selected_codepage: str | None = None,
        diagnostics: dict | None = None,
        partial_outputs: bool = False,
        progress_manifest: str = "",
        progress_manifest_payload: dict | None = None,
    ) -> ExtractionResult:
        return ExtractionResult(
            success=False,
            archive=archive,
            out_dir=out_dir,
            all_parts=list(all_parts or []),
            error=error,
            password_used=password_used,
            selected_codepage=selected_codepage,
            diagnostics=dict(diagnostics or {}),
            partial_outputs=partial_outputs,
            progress_manifest=progress_manifest,
            progress_manifest_payload=progress_manifest_payload,
        )

    @staticmethod
    def _diagnostics_from(result: object) -> dict:
        diagnostics = getattr(result, "worker_diagnostics", None)
        return dict(diagnostics) if isinstance(diagnostics, dict) else {}

    @staticmethod
    def _empty_repaired_success(diagnostics: dict, task: ArchiveTask) -> bool:
        result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
        if str(result.get("status") or "") != "ok":
            return False
        if int(result.get("item_count", 0) or 0) > 0:
            return False
        if int(result.get("files_written", 0) or 0) > 0 or int(result.get("bytes_written", 0) or 0) > 0:
            return False
        try:
            state = task.archive_state()
        except Exception:
            return False
        return bool(getattr(state, "patches", None))
