import os
import shutil
import subprocess
from contextlib import nullcontext
from typing import Any, Callable, Optional

from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.tasks import ArchiveTask, SplitArchiveInfo
from sunpack.extraction.internal.workflow.errors import classify_extract_failure
from sunpack.extraction.internal.workflow.retry_policy import ExtractRetryPolicy
from sunpack.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from sunpack.extraction.internal.sevenzip.worker_diagnostics import compact_success_worker_diagnostics
from sunpack.extraction.internal.workflow.split_entry import SplitEntryResolver
from sunpack.extraction.progress import has_recoverable_partial_outputs, write_extraction_progress_manifest_payload
from sunpack.contracts.extraction import ExtractionResult
from sunpack.passwords.result import PasswordResolution, PasswordResolutionStatus
from sunpack.passwords.internal.local_files import directory_password_context_from_task
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.output_inventory import OutputInventory, collect_output_inventory
from sunpack.i18n import I18nContext


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
        write_progress_manifest: bool = False,
        quiet: bool = False,
        language: str = "en",
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
        self.write_progress_manifest = bool(write_progress_manifest)
        self.quiet = bool(quiet)
        self.i18n = I18nContext(language)

    def extract(
        self,
        task: ArchiveTask,
        out_dir: str,
        split_info: Optional[SplitArchiveInfo] = None,
        runtime_scheduler: Any = None,
        *,
        allow_embedded_segments: bool = True,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "extract",
    ) -> ExtractionResult:
        if allow_embedded_segments:
            with _phase(phase_timer, f"{phase_prefix}_read_extractable_segments"):
                segments = [
                    dict(item)
                    for item in knowledge_view.analysis_extractable_segments(task)
                    if isinstance(item, dict) and isinstance(item.get("archive_input"), dict)
                ]
            if segments:
                return self._extract_embedded_segments(
                    task,
                    out_dir,
                    segments,
                    split_info=split_info,
                    runtime_scheduler=runtime_scheduler,
                    phase_timer=phase_timer,
                    phase_prefix=f"{phase_prefix}_embedded",
                )

        archive = task.main_path
        split_info = split_info or task.split_info
        with _phase(phase_timer, f"{phase_prefix}_resolve_split_entry"):
            archive, all_parts, split_info = self.split_entry_resolver.resolve(
                archive,
                list(task.all_parts or [archive]),
                split_info,
            )
        is_split = split_info.is_split or len(all_parts) > 1

        self._log(self.i18n.t("extract.log.start", archive=archive))

        if not self.ensure_space(5):
            failure = self._failure_info(FailureKind.PROCESS_ERROR, "preflight", "failure.insufficient_space")
            return self._failed(
                archive,
                out_dir,
                all_parts,
                self._localized_failure(failure),
                failure=failure,
                diagnostics={"failure_stage": "preflight", "failure_kind": "disk_space"},
            )

        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as exc:
            failure = self._failure_info(FailureKind.FILESYSTEM_ERROR, "preflight", "extract.dir_create_failed", error=str(exc))
            return self._failed(
                archive,
                out_dir,
                all_parts,
                self._localized_failure(failure),
                failure=failure,
                diagnostics={"failure_stage": "preflight", "failure_kind": "output_filesystem", "message": str(exc)},
            )

        with _phase(phase_timer, f"{phase_prefix}_startupinfo"):
            startupinfo = self._startupinfo()
        retry_count = 0
        # The initial preflight already checked the same requirement.  Recheck
        # only after an extraction attempt, when disk usage may have changed.
        space_checked = True
        password_candidate_rejections = 0
        password_candidate_inconclusive: FailureInfo | None = None
        password_candidates_inconclusive = 0
        while retry_count < self.retry_policy.max_retries:
            with _phase(phase_timer, f"{phase_prefix}_ensure_space_retry"):
                has_space = space_checked or self.ensure_space(5)
                space_checked = False
            if not has_space:
                shutil.rmtree(out_dir, ignore_errors=True)
                failure = self._failure_info(FailureKind.PROCESS_ERROR, "preflight", "failure.insufficient_space")
                return self._failed(
                    archive,
                    out_dir,
                    all_parts,
                    self._localized_failure(failure),
                    failure=failure,
                    diagnostics={"failure_stage": "preflight", "failure_kind": "disk_space"},
                )
            try:
                with _phase(phase_timer, f"{phase_prefix}_mkdir_retry"):
                    os.makedirs(out_dir, exist_ok=True)
            except Exception as exc:
                failure = self._failure_info(FailureKind.FILESYSTEM_ERROR, "preflight", "extract.dir_create_failed", error=str(exc))
                return self._failed(
                    archive,
                    out_dir,
                    all_parts,
                    self._localized_failure(failure),
                    failure=failure,
                    diagnostics={"failure_stage": "preflight", "failure_kind": "output_filesystem", "message": str(exc)},
                )

            descriptor = split_info.archive_input or task.archive_input()
            run_archive = descriptor.entry_path
            run_parts = descriptor.part_paths()
            cleanup_parts = list(run_parts)
            run_result = None
            test_result = None
            err = ""
            correct_pwd = None
            selected_codepage = None

            try:
                with _phase(phase_timer, f"{phase_prefix}_resolve_password"):
                    resolution = self._resolve_password(task, run_archive, run_parts)
                resolution_failure = self._password_resolution_failure(resolution)
                if resolution_failure is not None:
                    shutil.rmtree(out_dir, ignore_errors=True)
                    self._log(self.i18n.t("extract.log.failed", archive=archive, error=self._localized_failure(resolution_failure)))
                    return self._failed(
                        archive,
                        out_dir,
                        run_parts,
                        self._localized_failure(resolution_failure),
                        failure=resolution_failure,
                        diagnostics={
                            "failure_stage": resolution_failure.stage,
                            "failure_kind": resolution_failure.kind.value,
                            "message": resolution.error_text,
                        },
                    )
                correct_pwd = resolution.password
                test_result = resolution.test_result
                test_err = resolution.error_text
                with _phase(phase_timer, f"{phase_prefix}_scan_filename_encoding"):
                    try:
                        format_hint = task.archive_input().format_hint
                    except (TypeError, ValueError, AttributeError):
                        format_hint = str(getattr(task, "detected_ext", "") or "").lstrip(".")
                    scan_for_task = getattr(self.metadata_scanner, "scan_for_task", None)
                    if scan_for_task is not None:
                        filename_encoding = scan_for_task(
                            task, run_archive, password=correct_pwd,
                            part_paths=run_parts, format_hint=format_hint,
                        )
                    else:
                        filename_encoding = self.metadata_scanner.scan(
                            run_archive, password=correct_pwd,
                            part_paths=run_parts, format_hint=format_hint,
                        )
                    selected_codepage = filename_encoding.selected_codepage
                    if filename_encoding.error:
                        # Filename detection is an optional override.  Failure or
                        # ambiguity must not prevent the archive backend from
                        # using UTF-8 flags / Unicode extra fields itself.
                        self._log(
                            self.i18n.t("extract.log.metadata_override_not_used", error=filename_encoding.error)
                        )
                        selected_codepage = None
                        filename_encoding.decoded_names = []

                if correct_pwd is None:
                    err = test_err
                else:
                    with _phase(phase_timer, f"{phase_prefix}_sevenzip_run_extract"):
                        run_result = self.sevenzip_runner.run_extract(
                            archive_path=run_archive,
                            part_paths=run_parts,
                            out_dir=out_dir,
                            password=correct_pwd,
                            selected_codepage=selected_codepage,
                            decoded_names=filename_encoding.decoded_names,
                            startupinfo=startupinfo,
                            runtime_scheduler=runtime_scheduler,
                            task=task,
                            phase_timer=phase_timer,
                            phase_prefix=f"{phase_prefix}_sevenzip",
                        )

                    if run_result.returncode == 0:
                        if resolution.requires_extraction_confirmation:
                            self.password_resolver.confirm_extraction(resolution)
                        with _phase(phase_timer, f"{phase_prefix}_diagnostics_success"):
                            diagnostics = self._diagnostics_from(run_result)
                            if resolution.requires_extraction_confirmation:
                                diagnostics["password_verification"] = "extraction_transaction"
                                diagnostics["password_candidates_rejected"] = password_candidate_rejections
                                diagnostics["password_candidates_inconclusive"] = password_candidates_inconclusive
                        with _phase(phase_timer, f"{phase_prefix}_output_stats_success"):
                            worker_result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
                            output_inventory = collect_output_inventory(out_dir, worker_result)
                            compact_success_worker_diagnostics(diagnostics)
                            output_stats = {
                                "file_count": output_inventory.stats.file_count,
                                "total_bytes": output_inventory.stats.total_size,
                            }
                            self._fill_success_output_counts(diagnostics, output_stats)
                        with _phase(phase_timer, f"{phase_prefix}_empty_repaired_success_check"):
                            empty_repaired_success = self._empty_repaired_success(diagnostics, task)
                        if empty_repaired_success:
                            failure = self._failure_info(
                                FailureKind.DAMAGED,
                                "verification",
                                "failure.no_extractable_repair_output",
                                repairable=True,
                            )
                            self._log(self.i18n.t("extract.log.failed", archive=archive, error=self._localized_failure(failure)))
                            shutil.rmtree(out_dir, ignore_errors=True)
                            diagnostics["failure_stage"] = "verification"
                            diagnostics["failure_kind"] = "empty_repair_output"
                            return self._failed(
                                archive,
                                out_dir,
                                run_parts,
                                self._localized_failure(failure),
                                failure=failure,
                                password_used=correct_pwd,
                                selected_codepage=selected_codepage,
                                diagnostics=diagnostics,
                            )
                        self._log(self.i18n.t("extract.log.success", archive=archive))
                        manifest_path = ""
                        manifest_payload = None
                        if diagnostics.get("result"):
                            with _phase(phase_timer, f"{phase_prefix}_write_success_manifest"):
                                manifest_path, manifest_payload = write_extraction_progress_manifest_payload(
                                    archive=archive,
                                    out_dir=out_dir,
                                    diagnostics=diagnostics,
                                    round_index=retry_count + 1,
                                    write_file=self.write_progress_manifest,
                                )
                            if manifest_path:
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
                            output_inventory=output_inventory,
                            files_written=output_stats["file_count"],
                            bytes_written=output_stats["total_bytes"],
                        )

                    err = f"{run_result.stdout}\n{run_result.stderr}".lower()
            finally:
                pass

            if resolution.requires_extraction_confirmation and run_result is not None:
                candidate_failure = classify_extract_failure(
                    run_result,
                    err,
                    archive=archive,
                    is_split_archive=is_split,
                    password_evidence=resolution.candidate_evidence,
                )
                candidate_failure = self._downgrade_ambiguous_split_empty_password(
                    resolution,
                    candidate_failure,
                    is_split=is_split,
                )
                if candidate_failure.details.get("evidence") == "zipcrypto_entry_crc_proven_before_failure":
                    self.password_resolver.confirm_extraction(resolution)
                elif candidate_failure.kind == FailureKind.PASSWORD_INCONCLUSIVE:
                    password_candidates_inconclusive += 1
                    if password_candidate_inconclusive is None:
                        password_candidate_inconclusive = candidate_failure
                    if self.password_resolver.has_pending_candidates(resolution.archive_key):
                        shutil.rmtree(out_dir, ignore_errors=True)
                        continue
                elif candidate_failure.is_password_failure:
                    self.password_resolver.reject_extraction_candidate(resolution)
                    password_candidate_rejections += 1
                    if self.password_resolver.has_pending_candidates(resolution.archive_key):
                        shutil.rmtree(out_dir, ignore_errors=True)
                        if password_candidate_rejections == 1 or password_candidate_rejections % 50 == 0:
                            self._log(
                                self.i18n.t("extract.log.password_rejections", count=password_candidate_rejections, archive=archive)
                            )
                        continue

            if self.retry_policy.can_retry(run_result, err, retry_count, archive, is_split):
                retry_count += 1
                if self.retry_policy.needs_space_recheck(run_result, err) and not self.ensure_space(10):
                    shutil.rmtree(out_dir, ignore_errors=True)
                    failure = self._failure_info(FailureKind.PROCESS_ERROR, "retry_preflight", "failure.insufficient_space")
                    return self._failed(
                        archive,
                        out_dir,
                        all_parts,
                        self._localized_failure(failure),
                        failure=failure,
                        diagnostics={"failure_stage": "retry_preflight", "failure_kind": "disk_space"},
                    )
                shutil.rmtree(out_dir, ignore_errors=True)
                self._log(self.i18n.t("extract.log.temp_retry", attempt=retry_count + 1, max_attempts=self.retry_policy.max_retries, archive=archive))
                self.retry_policy.backoff(retry_count)
                continue

            with _phase(phase_timer, f"{phase_prefix}_classify_error"):
                failure = classify_extract_failure(
                    run_result or test_result,
                    err,
                    archive=archive,
                    is_split_archive=is_split,
                    password_evidence=resolution.candidate_evidence,
                )
                if password_candidate_inconclusive is not None and failure.is_password_failure:
                    failure = password_candidate_inconclusive
                error_msg = self._append_retry_count(self._localized_failure(failure), retry_count)
            self._log(self.i18n.t("extract.log.failed", archive=archive, error=error_msg))
            with _phase(phase_timer, f"{phase_prefix}_diagnostics_failure"):
                diagnostics = self._diagnostics_from(run_result or test_result)
                if resolution.requires_extraction_confirmation:
                    diagnostics["password_candidates_rejected"] = password_candidate_rejections
                    diagnostics["password_candidates_inconclusive"] = password_candidates_inconclusive
            with _phase(phase_timer, f"{phase_prefix}_recoverable_partial_check"):
                recoverable_partial = (
                    failure.kind != FailureKind.PASSWORD_INCONCLUSIVE
                    and self.best_effort
                    and has_recoverable_partial_outputs(diagnostics, out_dir)
                )
            if recoverable_partial:
                with _phase(phase_timer, f"{phase_prefix}_write_partial_manifest"):
                    manifest_path, manifest_payload = write_extraction_progress_manifest_payload(
                        archive=archive,
                        out_dir=out_dir,
                        diagnostics=diagnostics,
                        round_index=retry_count + 1,
                        write_file=self.write_progress_manifest,
                    )
                diagnostics["partial_outputs"] = True
                if manifest_path:
                    diagnostics["progress_manifest"] = manifest_path
                return self._failed(
                    archive,
                    out_dir,
                    run_parts,
                    error_msg,
                    failure=failure,
                    password_used=(None if failure.kind == FailureKind.PASSWORD_INCONCLUSIVE else correct_pwd),
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
                failure=failure,
                password_used=(None if failure.kind == FailureKind.PASSWORD_INCONCLUSIVE else correct_pwd),
                selected_codepage=selected_codepage,
                diagnostics=diagnostics,
            )

        shutil.rmtree(out_dir, ignore_errors=True)
        failure = self._failure_info(FailureKind.PROCESS_ERROR, "retry_exhausted", "failure.insufficient_space")
        return self._failed(
            archive,
            out_dir,
            all_parts,
            self._localized_failure(failure),
            failure=failure,
            diagnostics={"failure_stage": "retry_exhausted", "failure_kind": "unknown"},
        )

    def _resolve_password(self, task: ArchiveTask, archive_path: str, part_paths: list[str]):
        directory_passwords = directory_password_context_from_task(task)
        known_password = knowledge_view.archive_password(task)
        if known_password is not None:
            return PasswordResolution(
                password=str(known_password),
                status=PasswordResolutionStatus.RESOLVED,
                archive_key=task.key,
            )
        archive_state = task.archive_state() if hasattr(task, "archive_state") else None
        if archive_state is not None and archive_state.patches:
            if not self._task_requires_password(task):
                return PasswordResolution(
                    password="",
                    status=PasswordResolutionStatus.UNENCRYPTED,
                    archive_key=task.key,
                    encrypted=False,
                )
            return PasswordResolution(
                password=None,
                status=PasswordResolutionStatus.PASSWORD_REQUIRED,
                archive_key=task.key,
                encrypted=True,
                error_text="password verification is unsupported for patched archive state without a resolved password",
            )
        if not self._password_store_has_candidates(directory_passwords) and not self._task_requires_password(task):
            return PasswordResolution(
                password="",
                status=PasswordResolutionStatus.UNENCRYPTED,
                archive_key=task.key,
                encrypted=False,
            )
        return self.password_resolver.resolve(
            archive_path,
            task.fact_bag,
            part_paths=part_paths,
            archive_key=task.key,
            directory_passwords=directory_passwords,
        )

    @staticmethod
    def _task_requires_password(task: ArchiveTask) -> bool:
        health = knowledge_view.resource_health(task)
        if isinstance(health, dict) and (health.get("is_encrypted") or health.get("is_wrong_password")):
            return True
        return False

    def _password_store_has_candidates(self, directory_passwords: list[str]) -> bool:
        try:
            return bool(self.password_store.has_candidates(directory_passwords=directory_passwords))
        except TypeError:
            return bool(directory_passwords or self.password_store.has_candidates())

    def _startupinfo(self):
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
        failure: FailureInfo | None = None,
        password_used: str | None = None,
        selected_codepage: str | None = None,
        diagnostics: dict | None = None,
        partial_outputs: bool = False,
        progress_manifest: str = "",
        progress_manifest_payload: dict | None = None,
    ) -> ExtractionResult:
        diagnostic_payload = dict(diagnostics or {})
        if failure is not None:
            diagnostic_payload.setdefault("failure_stage", failure.stage)
            diagnostic_payload.setdefault("failure_kind", failure.kind.value)
            diagnostic_payload["failure"] = failure.to_dict()
        return ExtractionResult(
            success=False,
            archive=archive,
            out_dir=out_dir,
            all_parts=list(all_parts or []),
            error=error,
            failure=failure,
            password_used=password_used,
            selected_codepage=selected_codepage,
            diagnostics=diagnostic_payload,
            partial_outputs=partial_outputs,
            progress_manifest=progress_manifest,
            progress_manifest_payload=progress_manifest_payload,
        )

    def _localized_failure(self, failure: FailureInfo) -> str:
        if failure.message_key:
            return self.i18n.t(failure.message_key, **failure.message_params)
        return failure.message

    def _append_retry_count(self, error: str, retry_count: int) -> str:
        try:
            return self.retry_policy.append_retry_count(error, retry_count, self.i18n)
        except TypeError:
            return self.retry_policy.append_retry_count(error, retry_count)

    def _failure_info(
        self,
        kind: FailureKind,
        stage: str,
        message_key: str,
        *,
        user_action: str = "",
        repairable: bool = False,
        **params,
    ) -> FailureInfo:
        return FailureInfo(
            kind=kind,
            stage=stage,
            message=self.i18n.t(message_key, **params),
            message_key=message_key,
            message_params=dict(params),
            user_action=user_action,
            repairable=repairable,
        )

    @staticmethod
    def _diagnostics_from(result: object) -> dict:
        diagnostics = getattr(result, "worker_diagnostics", None)
        return dict(diagnostics) if isinstance(diagnostics, dict) else {}

    def _password_resolution_failure(self, resolution: PasswordResolution) -> FailureInfo | None:
        if resolution.password is not None:
            return None
        mapping = {
            PasswordResolutionStatus.PASSWORD_REQUIRED: (
                FailureKind.PASSWORD_REQUIRED,
                "failure.password_required",
                "request_password",
                False,
            ),
            PasswordResolutionStatus.CANDIDATES_EXHAUSTED: (
                FailureKind.WRONG_PASSWORD,
                "failure.password_wrong_or_unknown",
                "request_password",
                False,
            ),
            PasswordResolutionStatus.INCONCLUSIVE: (
                FailureKind.PASSWORD_INCONCLUSIVE,
                "failure.password_state_unknown",
                "",
                False,
            ),
            PasswordResolutionStatus.DAMAGED: (
                FailureKind.DAMAGED,
                "failure.damaged",
                "",
                True,
            ),
            PasswordResolutionStatus.UNSUPPORTED: (
                FailureKind.UNSUPPORTED,
                "failure.unsupported",
                "",
                False,
            ),
            PasswordResolutionStatus.BACKEND_ERROR: (
                FailureKind.BACKEND_UNAVAILABLE,
                "failure.password_verifier_unavailable",
                "",
                False,
            ),
        }
        spec = mapping.get(resolution.status)
        if spec is None:
            return None
        kind, message_key, user_action, repairable = spec
        return FailureInfo(
            kind=kind,
            stage="password_resolution",
            message=self.i18n.t(message_key),
            message_key=message_key,
            user_action=user_action,
            repairable=repairable,
            details={"diagnostic": resolution.error_text},
        )

    @staticmethod
    def _downgrade_ambiguous_split_empty_password(
        resolution: PasswordResolution,
        failure: FailureInfo,
        *,
        is_split: bool,
    ) -> FailureInfo:
        """Do not turn an incomplete split stream into password evidence.

        With an unknown encryption state the resolver deliberately tries the
        empty password as an extraction transaction.  Some archive backends
        report a truncated split stream as ``wrong_password``.  Rejecting the
        empty candidate in that situation poisons the fingerprint cache and
        creates a password-only watch blocker.  Positive encryption facts and
        non-empty user/store candidates retain the normal password behavior.
        """
        if (
            not is_split
            or failure.kind is not FailureKind.WRONG_PASSWORD
            or resolution.password != ""
            or resolution.encrypted is True
        ):
            return failure
        return FailureInfo(
            kind=FailureKind.PASSWORD_INCONCLUSIVE,
            stage=failure.stage,
            message_key="failure.password_state_unknown",
            message=failure.message,
            repairable=False,
            details={
                **dict(failure.details or {}),
                "evidence": "ambiguous_empty_password_on_split_input",
                "original_failure": failure.to_dict(),
            },
        )

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

    def _extract_embedded_segments(
        self,
        task: ArchiveTask,
        out_dir: str,
        segments: list[dict[str, Any]],
        *,
        split_info: Optional[SplitArchiveInfo] = None,
        runtime_scheduler: Any = None,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "extract_embedded",
    ) -> ExtractionResult:
        archive = task.main_path
        split_info = split_info or task.split_info
        all_parts = list(task.all_parts or [archive])
        self._log(self.i18n.t("extract.log.embedded_start", archive=archive, count=len(segments)))
        with _phase(phase_timer, f"{phase_prefix}_ensure_space_initial"):
            has_space = self.ensure_space(5)
        if not has_space:
            failure = self._failure_info(FailureKind.PROCESS_ERROR, "preflight", "failure.insufficient_space")
            return self._failed(
                archive,
                out_dir,
                all_parts,
                self._localized_failure(failure),
                failure=failure,
                diagnostics={"failure_stage": "preflight", "failure_kind": "disk_space"},
            )
        try:
            with _phase(phase_timer, f"{phase_prefix}_mkdir_initial"):
                os.makedirs(out_dir, exist_ok=True)
        except Exception as exc:
            failure = self._failure_info(FailureKind.FILESYSTEM_ERROR, "preflight", "extract.dir_create_failed", error=str(exc))
            return self._failed(
                archive,
                out_dir,
                all_parts,
                self._localized_failure(failure),
                failure=failure,
                diagnostics={"failure_stage": "preflight", "failure_kind": "output_filesystem", "message": str(exc)},
            )

        with _phase(phase_timer, f"{phase_prefix}_save_archive_facts"):
            saved_archive_facts = {
                key: value
                for key, value in task.fact_bag.to_dict().items()
                if key.startswith("archive.")
            }
        segment_results: list[dict[str, Any]] = []
        password_used = None
        selected_codepage = None
        any_success = False
        any_partial = False
        segment_failures: list[FailureInfo] = []

        for position, segment in enumerate(segments, start=1):
            fmt = str(segment.get("format") or "archive").replace("/", "_") or "archive"
            segment_id = str(segment.get("segment_id") or f"embedded_{position:02d}_{fmt}")
            # A single embedded payload is the logical archive represented by
            # this task (the common SFX case).  Extract it at the task output
            # root so manifest paths continue to match.  Multiple independent
            # payloads still need isolated subdirectories to avoid collisions.
            segment_dir = (
                out_dir
                if len(segments) == 1
                else os.path.join(out_dir, self._safe_segment_dir_name(segment_id, position, fmt))
            )
            with _phase(phase_timer, f"{phase_prefix}_segment_descriptor"):
                descriptor = ArchiveInputDescriptor.from_any(
                    segment.get("archive_input") if isinstance(segment.get("archive_input"), dict) else None,
                    archive_path=archive,
                    part_paths=all_parts,
                    format_hint=str(segment.get("format") or ""),
                    logical_name=str(segment.get("logical_name") or segment_id),
                )
            try:
                with _phase(phase_timer, f"{phase_prefix}_segment_set_archive_state"):
                    task.set_archive_state(ArchiveState.from_archive_input(descriptor))
                result = self.extract(
                    task,
                    segment_dir,
                    split_info=split_info,
                    runtime_scheduler=runtime_scheduler,
                    allow_embedded_segments=False,
                    phase_timer=phase_timer,
                    phase_prefix=f"{phase_prefix}_segment_extract",
                )
            finally:
                with _phase(phase_timer, f"{phase_prefix}_segment_restore_archive_facts"):
                    self._restore_archive_facts(task, saved_archive_facts)

            if result.password_used is not None and password_used is None:
                password_used = result.password_used
            if result.selected_codepage is not None and selected_codepage is None:
                selected_codepage = result.selected_codepage
            with _phase(phase_timer, f"{phase_prefix}_segment_directory_stats"):
                segment_inventory = OutputInventory.from_value(
                    result.output_inventory or result.output_inventory_payload,
                    expected_root=segment_dir,
                )
                stats = {
                    "file_count": segment_inventory.stats.file_count,
                    "total_bytes": segment_inventory.stats.total_size,
                } if segment_inventory is not None else self._directory_stats(segment_dir)
            segment_success = bool(result.success)
            segment_partial = bool(result.partial_outputs or stats["file_count"] > 0)
            any_success = any_success or segment_success
            any_partial = any_partial or segment_partial
            if result.failure is not None:
                segment_failures.append(result.failure)
            segment_results.append({
                "segment_id": segment_id,
                "index": int(segment.get("index") or position),
                "format": segment.get("format") or "",
                "logical_name": segment.get("logical_name") or "",
                "start_offset": segment.get("start_offset"),
                "end_offset": segment.get("end_offset"),
                "confidence": segment.get("confidence"),
                "archive_input": segment.get("archive_input"),
                "out_dir": segment_dir,
                "success": segment_success,
                "partial_outputs": segment_partial,
                "error": result.error,
                "failure": result.failure.to_dict() if result.failure is not None else None,
                "diagnostics": dict(result.diagnostics or {}),
                "progress_manifest": result.progress_manifest,
                "files_written": stats["file_count"],
                "bytes_written": stats["total_bytes"],
            })

        with _phase(phase_timer, f"{phase_prefix}_directory_stats_total"):
            output_inventory = collect_output_inventory(out_dir)
            totals = {
                "file_count": output_inventory.stats.file_count,
                "total_bytes": output_inventory.stats.total_size,
            }
        diagnostics = {
            "result": {
                "status": "ok" if any_success else ("partial" if any_partial else "failed"),
                "embedded_segment_count": len(segment_results),
                "embedded_success_count": sum(1 for item in segment_results if item.get("success")),
                "files_written": totals["file_count"],
                "bytes_written": totals["total_bytes"],
                "item_count": totals["file_count"],
            },
            "embedded_segments": segment_results,
        }
        successful_segments = [item for item in segment_results if item.get("success")]
        if len(segment_results) == 1 and len(successful_segments) == 1:
            # Verification must inspect the logical embedded archive rather
            # than the SFX carrier.  In particular, an executable carrier is
            # intentionally not extractable as ZIP itself and would otherwise
            # downgrade a fully verified embedded ZIP to partial success.
            verification_input = successful_segments[0].get("archive_input")
            if isinstance(verification_input, dict):
                diagnostics["verification_archive_input"] = dict(verification_input)
        if any_success:
            manifest_path = ""
            manifest_payload = None
            if self.write_progress_manifest:
                with _phase(phase_timer, f"{phase_prefix}_write_manifest"):
                    manifest_path, manifest_payload = write_extraction_progress_manifest_payload(
                        archive=archive,
                        out_dir=out_dir,
                        diagnostics=diagnostics,
                        round_index=1,
                        write_file=self.write_progress_manifest,
                    )
                if manifest_path:
                    diagnostics["progress_manifest"] = manifest_path
            self._log(self.i18n.t("extract.log.embedded_success", archive=archive))
            return ExtractionResult(
                success=True,
                archive=archive,
                out_dir=out_dir,
                all_parts=all_parts,
                password_used=password_used,
                selected_codepage=selected_codepage,
                diagnostics=diagnostics,
                partial_outputs=any_partial and not all(item.get("success") for item in segment_results),
                progress_manifest=manifest_path,
                progress_manifest_payload=manifest_payload,
                output_inventory=output_inventory,
                files_written=totals["file_count"],
                bytes_written=totals["total_bytes"],
            )
        self._log(self.i18n.t("extract.log.embedded_failed", archive=archive))
        password_failure = any(failure.is_password_failure for failure in segment_failures)
        message_key = "failure.embedded_wrong_password" if password_failure else "failure.embedded_extract_failed"
        aggregate_failure = FailureInfo(
            kind=FailureKind.EMBEDDED_SEGMENTS_FAILED,
            stage="embedded_segments",
            message=self.i18n.t(message_key),
            message_key=message_key,
            user_action="request_password" if password_failure else "",
            repairable=bool(segment_failures) and all(failure.repairable for failure in segment_failures),
            causes=tuple(segment_failures),
            details={"segment_count": len(segment_results)},
        )
        return self._failed(
            archive,
            out_dir,
            all_parts,
            aggregate_failure.message,
            failure=aggregate_failure,
            password_used=password_used,
            selected_codepage=selected_codepage,
            diagnostics={
                **diagnostics,
                "failure_stage": "embedded_segments",
                "failure_kind": "embedded_extraction_failed",
            },
            partial_outputs=any_partial,
        )

    @staticmethod
    def _safe_segment_dir_name(segment_id: str, position: int, fmt: str) -> str:
        raw = segment_id or f"embedded_{position:02d}_{fmt or 'archive'}"
        safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in raw)
        return safe or f"embedded_{position:02d}_{fmt or 'archive'}"

    @staticmethod
    def _restore_archive_facts(task: ArchiveTask, saved: dict[str, Any]) -> None:
        current_keys = [key for key in task.fact_bag.to_dict() if key.startswith("archive.")]
        for key in current_keys:
            task.fact_bag.unset(key)
        for key, value in saved.items():
            task.fact_bag.set(key, value)

    @staticmethod
    def _directory_stats(path: str) -> dict[str, int]:
        file_count = 0
        total_bytes = 0
        if not os.path.isdir(path):
            return {"file_count": 0, "total_bytes": 0}
        for root, _dirs, files in os.walk(path):
            for name in files:
                file_count += 1
                try:
                    total_bytes += int(os.path.getsize(os.path.join(root, name)))
                except OSError:
                    pass
        return {"file_count": file_count, "total_bytes": total_bytes}

    @staticmethod
    def _fill_success_output_counts(diagnostics: dict[str, Any], stats: dict[str, int]) -> None:
        result = diagnostics.get("result")
        if not isinstance(result, dict):
            result = {}
            diagnostics["result"] = result
        result.setdefault("status", "ok")
        result["files_written"] = int(stats.get("file_count", 0) or 0)
        result["bytes_written"] = int(stats.get("total_bytes", 0) or 0)
        result["item_count"] = max(int(result.get("item_count", 0) or 0), int(stats.get("file_count", 0) or 0))

    def _log(self, message: str) -> None:
        if not self.quiet:
            print(message)


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
