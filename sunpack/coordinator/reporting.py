import os
import shutil
import sys
import threading
import time
from typing import Any, List

from sunpack.contracts.failures import FailureInfo
from sunpack.repair.config import repair_system_mode


class RunReporter:
    """Thread-safe, user-facing progress for one pipeline run."""

    def __init__(self, language: str = "en", quiet: bool = False, verbose: bool = False):
        self.language = "zh" if str(language or "").strip().lower() == "zh" else "en"
        self.quiet = bool(quiet)
        self.verbose = bool(verbose)
        self._lock = threading.Lock()
        self._total_tasks = 0
        self._completed_tasks = 0
        self._nested_tasks = 0
        self._max_depth = 0
        self._task_lineages: dict[int, tuple[str, ...]] = {}
        self._output_lineages: dict[str, tuple[str, ...]] = {}
        self._top_level_outputs: list[str] = []
        self._interactive = not self.quiet and _terminal_supports_updates(sys.stdout)
        self._use_color = self._interactive and os.environ.get("NO_COLOR") is None
        self._panel_tasks: list[int] = []
        self._task_rows: dict[int, dict[str, Any]] = {}
        self._last_render_at = 0.0

    def text(self, en: str, zh: str) -> str:
        return zh if self.language == "zh" else en

    def scan_started(self, round_index: int) -> None:
        if self.quiet:
            return
        depth = max(1, int(round_index or 1))
        with self._lock:
            print(self.text(
                "[Scanning] Looking for archives..." if depth == 1 else f"[Recursive scan] Checking level {depth}...",
                "[扫描中] 正在查找压缩包…" if depth == 1 else f"[递归扫描] 正在检查第 {depth} 层…",
            ), flush=True)

    def begin_round(self, round_index: int, tasks: list[Any], direct: bool = False) -> None:
        depth = max(1, int(round_index or 1))
        with self._lock:
            for task in tasks:
                parent_lineage = self._lineage_for_path(str(getattr(task, "main_path", "") or ""))
                self._task_lineages[id(task)] = parent_lineage
                self._task_rows[id(task)] = {
                    "task": task,
                    "depth": depth,
                    "lineage": parent_lineage,
                    "state": "waiting",
                    "progress": 0.0,
                    "completed_bytes": 0,
                    "total_bytes": 0,
                    "detail": "",
                }
            self._total_tasks += len(tasks)
            if depth > 1:
                self._nested_tasks += len(tasks)
            if tasks:
                self._max_depth = max(self._max_depth, depth)
            if self.quiet:
                return
            if direct and depth == 1:
                message = self.text(
                    f"[Ready] {len(tasks)} archive(s) to process",
                    f"[准备完成] 将处理 {len(tasks)} 个压缩包",
                )
            elif depth == 1:
                message = self.text(
                    f"[Scan] Found {len(tasks)} archive(s) to process",
                    f"[扫描完成] 发现 {len(tasks)} 个待处理压缩包",
                )
            else:
                message = self.text(
                    f"[Recursive scan] Level {depth}: found {len(tasks)} nested archive(s)",
                    f"[递归扫描] 第 {depth} 层发现 {len(tasks)} 个嵌套压缩包",
                )
            print(message, flush=True)
            if self._interactive:
                self._panel_tasks = [id(task) for task in tasks]
                for task_id in self._panel_tasks:
                    print(self._format_task_row(self._task_rows[task_id]), flush=True)

    def task_started(self, task: Any, round_index: int) -> None:
        if self.quiet:
            return
        with self._lock:
            if self._interactive:
                self._update_task_locked(task, state="preparing", force=True)
                return
            depth = max(1, int(round_index or 1))
            name = _task_name(task)
            prefix = self._tree_prefix(depth)
            progress = f"{self._completed_tasks}/{self._total_tasks}"
            print(self.text(
                f"{prefix}[Processing {progress}] {name}",
                f"{prefix}[处理中 {progress}] {name}",
            ), flush=True)

    def task_status(self, task: Any, state: str, detail: str = "") -> None:
        if self.quiet:
            return
        with self._lock:
            if self._interactive:
                self._update_task_locked(task, state=state, detail=detail, force=True)
                return
            if state == "repairing":
                print(self.text(
                    f"[Repairing] {_task_name(task)}",
                    f"[正在修复] {_task_name(task)}",
                ), flush=True)

    def task_progress(self, task: Any, event: dict[str, Any]) -> None:
        if self.quiet or not self._interactive:
            return
        try:
            completed = max(0, int(event.get("completed_bytes", 0) or 0))
            total = max(0, int(event.get("total_bytes", 0) or 0))
        except (TypeError, ValueError):
            return
        progress = min(1.0, completed / total) if total > 0 else 0.0
        with self._lock:
            row = self._task_rows.get(id(task))
            if row is None:
                return
            old_percent = int(float(row.get("progress", 0.0)) * 100)
            new_percent = int(progress * 100)
            row.update({
                "state": "extracting",
                "progress": progress,
                "completed_bytes": completed,
                "total_bytes": total,
            })
            if new_percent != old_percent:
                self._render_panel_locked(force=False)

    def task_finished(self, task: Any, outcome: Any, round_index: int) -> None:
        with self._lock:
            depth = max(1, int(round_index or 1))
            self._completed_tasks += 1
            name = _task_name(task)
            parent_lineage = self._task_lineages.get(id(task), ())
            result = getattr(outcome, "result", outcome)
            out_dir = str(getattr(result, "out_dir", "") or "")
            success = bool(getattr(outcome, "success", getattr(result, "success", False)))
            partial = success and getattr(getattr(outcome, "verification", None), "decision_hint", "") == "accept_partial"
            if success and out_dir:
                lineage = (*parent_lineage, name)
                self._output_lineages[_absolute_key(out_dir)] = lineage
                if depth == 1 and out_dir not in self._top_level_outputs:
                    self._top_level_outputs.append(out_dir)

            if self.quiet:
                return
            if self._interactive:
                state = "partial" if partial else "complete" if success else "error"
                error = str(getattr(result, "error", "") or "") if not success else ""
                self._update_task_locked(
                    task,
                    state=state,
                    progress=1.0 if success else None,
                    detail=error,
                    force=True,
                )
                return
            prefix = self._tree_prefix(depth)
            progress = f"{self._completed_tasks}/{self._total_tasks}"
            if partial:
                status_en, status_zh = "Partially recovered", "部分恢复"
            elif success:
                status_en, status_zh = "Success", "成功"
            else:
                status_en, status_zh = "Failed", "失败"
            parent = " > ".join(parent_lineage)
            relation = self.text(f" (from {parent})", f"（来自 {parent}）") if parent else ""
            detail = ""
            if self.verbose and success and out_dir:
                detail = self.text(f" -> {out_dir}", f" -> {out_dir}")
            elif self.verbose and not success:
                error = str(getattr(result, "error", "") or "")
                detail = f"：{error}" if error else ""
            print(self.text(
                f"{prefix}[{status_en} {progress}] {name}{relation}{detail}",
                f"{prefix}[{status_zh} {progress}] {name}{relation}{detail}",
            ), flush=True)

    def log_final_summary(
        self,
        root_dir: str,
        start_time: float,
        success_count: int,
        failed_tasks: List[str],
        recovered_outputs: List[dict] | None = None,
        failures: List[FailureInfo] | None = None,
    ):
        recovered = list(recovered_outputs or [])
        partial_count = len(recovered)
        complete_count = max(0, int(success_count) - partial_count)
        failed_count = len(failed_tasks)
        elapsed = max(0.0, time.time() - start_time)

        if not self.quiet:
            print("\n" + self.text("Processing complete", "处理完成"))
            print("-" * 54)
            print(self.text(f"Time: {_duration(elapsed, 'en')}", f"耗时：{_duration(elapsed, 'zh')}"))
            print(self.text(
                f"Complete: {complete_count}  Partial: {partial_count}  Failed: {failed_count}",
                f"完整成功：{complete_count}  部分恢复：{partial_count}  失败：{failed_count}",
            ))
            if self._max_depth > 1:
                print(self.text(
                    f"Recursion: {self._max_depth} levels, {self._nested_tasks} nested archive(s)",
                    f"递归层级：{self._max_depth} 层，处理嵌套包：{self._nested_tasks} 个",
                ))
            output_location = self._output_location()
            if output_location:
                print(self.text(f"Output: {output_location}", f"输出位置：{output_location}"))

            for item in recovered:
                archive = os.path.basename(str(item.get("archive") or ""))
                coverage = item.get("archive_coverage") if isinstance(item.get("archive_coverage"), dict) else {}
                completeness = _percent(coverage.get("completeness", item.get("completeness", 0.0)))
                print(self.text(
                    f"[Partial] {archive}: {completeness}{_file_coverage(coverage)}",
                    f"[部分恢复] {archive}：完整度 {completeness}{_file_coverage(coverage)}",
                ))

        structured_failures = list(failures or [])
        if failed_tasks:
            if not self.quiet:
                for failed_task in failed_tasks:
                    print(self.text(f"[Failed] {failed_task}", f"[失败] {failed_task}"))
                if structured_failures and all(failure.is_password_failure for failure in structured_failures):
                    print(self.text(
                        "A password is required or the supplied passwords were rejected. Enter the correct password and retry.",
                        "压缩包需要密码或已有密码均不正确；请输入正确密码后重试。",
                    ))
                elif repair_system_mode() == "lite":
                    print(self.text(
                        "Repair is unavailable in this build; verification failures may indicate a damaged archive.",
                        "当前版本未包含模型修复系统；校验失败可能表示压缩包已损坏。",
                    ))
            log_path = os.path.join(root_dir, "failed_log.txt")
            try:
                with open(log_path, "w", encoding="utf-8") as handle:
                    for failed_task in failed_tasks:
                        handle.write(f"{failed_task}\n")
                    for failure in structured_failures:
                        handle.write(f"failure={failure.to_dict()}\n")
                if not self.quiet:
                    print(self.text(f"Failure details: {log_path}", f"失败详情：{log_path}"))
            except Exception:
                if not self.quiet:
                    print(self.text("[Error] Could not save the failure log.", "[错误] 无法保存失败日志。"))
        else:
            log_path = os.path.join(root_dir, "failed_log.txt")
            try:
                if os.path.exists(log_path):
                    os.remove(log_path)
            except OSError:
                pass
            if not self.quiet:
                print(self.text("All archives were processed successfully.", "所有压缩包均已处理成功。"))

        if not self.quiet:
            print("-" * 54)

    def _lineage_for_path(self, path: str) -> tuple[str, ...]:
        if not path:
            return ()
        candidate = _absolute_key(path)
        best_root = ""
        best_lineage: tuple[str, ...] = ()
        for output_root, lineage in self._output_lineages.items():
            try:
                inside = os.path.commonpath([candidate, output_root]) == output_root
            except ValueError:
                inside = False
            if inside and len(output_root) > len(best_root):
                best_root = output_root
                best_lineage = lineage
        return best_lineage

    def _update_task_locked(
        self,
        task: Any,
        *,
        state: str | None = None,
        progress: float | None = None,
        detail: str | None = None,
        force: bool = False,
    ) -> None:
        row = self._task_rows.get(id(task))
        if row is None:
            return
        if state is not None:
            row["state"] = state
        if progress is not None:
            row["progress"] = min(1.0, max(0.0, float(progress)))
        if detail is not None:
            row["detail"] = detail
        self._render_panel_locked(force=force)

    def _render_panel_locked(self, *, force: bool) -> None:
        if not self._interactive or not self._panel_tasks:
            return
        now = time.monotonic()
        if not force and now - self._last_render_at < 0.08:
            return
        self._last_render_at = now
        sys.stdout.write(f"\033[{len(self._panel_tasks)}A")
        for task_id in self._panel_tasks:
            row = self._task_rows.get(task_id)
            text = self._format_task_row(row) if row is not None else ""
            sys.stdout.write(f"\r\033[2K{text}\n")
        sys.stdout.flush()

    def _format_task_row(self, row: dict[str, Any]) -> str:
        depth = int(row.get("depth", 1) or 1)
        task = row.get("task")
        state = str(row.get("state") or "waiting")
        progress = float(row.get("progress", 0.0) or 0.0)
        percent = max(0, min(100, int(progress * 100)))
        filled = max(0, min(20, int(progress * 20)))
        bar = "#" * filled + "-" * (20 - filled)
        labels = {
            "waiting": ("Waiting", "等待队列"),
            "preparing": ("Preparing", "准备中"),
            "extracting": ("Extracting", "正在解压"),
            "repairing": ("Repairing", "正在修复"),
            "error": ("Error", "出现错误"),
            "partial": ("Partial", "部分恢复"),
            "complete": ("Complete", "完成"),
        }
        label = self.text(*labels.get(state, labels["waiting"]))
        colors = {
            "waiting": "\033[90m",
            "preparing": "\033[36m",
            "extracting": "\033[36m",
            "repairing": "\033[33m",
            "error": "\033[31m",
            "partial": "\033[33m",
            "complete": "\033[32m",
        }
        label = f"{label:^8}"
        if self._use_color:
            label = f"{colors.get(state, '')}{label}\033[0m"
        prefix = self._tree_prefix(depth)
        lineage = tuple(row.get("lineage") or ())
        parent = " > ".join(lineage)
        relation = self.text(f" (from {parent})", f"（来自 {parent}）") if parent else ""
        detail = str(row.get("detail") or "")
        if detail and (self.verbose or state == "error"):
            detail = f"：{detail}"
        else:
            detail = ""
        fixed_width = len(prefix) + 8 + len(bar) + 12
        available = max(12, shutil.get_terminal_size(fallback=(120, 30)).columns - fixed_width)
        suffix = _truncate_display(f"{_task_name(task)}{relation}{detail}", available)
        return f"{prefix}[{label}] [{bar}] {percent:3d}%  {suffix}"

    @staticmethod
    def _tree_prefix(depth: int) -> str:
        return "" if depth <= 1 else "  " * (depth - 1) + "└─ "

    def _output_location(self) -> str:
        outputs = [os.path.abspath(os.path.normpath(path)) for path in self._top_level_outputs if path]
        if not outputs:
            return ""
        if len(outputs) == 1:
            return outputs[0]
        try:
            return os.path.commonpath(outputs)
        except ValueError:
            return self.text("multiple locations", "多个位置")


def _task_name(task: Any) -> str:
    path = str(getattr(task, "main_path", "") or "")
    return os.path.basename(path) or str(getattr(task, "logical_name", "") or path or "archive")


def _absolute_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.normpath(path)))


def _terminal_supports_updates(stream: Any) -> bool:
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty) or not isatty():
        return False
    try:
        import ctypes

        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _truncate_display(text: str, max_width: int) -> str:
    if max_width <= 1:
        return "…"[:max_width]
    width = 0
    chars = []
    for char in text:
        char_width = 2 if ord(char) > 0xFF else 1
        if width + char_width > max_width:
            if chars:
                while chars and width + 1 > max_width:
                    removed = chars.pop()
                    width -= 2 if ord(removed) > 0xFF else 1
            return "".join(chars) + "…"
        chars.append(char)
        width += char_width
    return text


def _duration(seconds: float, language: str) -> str:
    total = max(0, int(round(seconds)))
    minutes, secs = divmod(total, 60)
    if minutes:
        return f"{minutes}m {secs}s" if language == "en" else f"{minutes} 分 {secs} 秒"
    return f"{secs}s" if language == "en" else f"{secs} 秒"


def _percent(value) -> str:
    try:
        return f"{float(value or 0.0) * 100:.1f}%"
    except (TypeError, ValueError):
        return "0.0%"


def _file_coverage(coverage: dict) -> str:
    expected = int(coverage.get("expected_files", 0) or 0)
    matched = int(coverage.get("matched_files", 0) or 0)
    complete = int(coverage.get("complete_files", 0) or 0)
    if expected <= 0:
        return ""
    return f" ({complete}/{matched}/{expected})"
