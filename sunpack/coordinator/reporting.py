import os
import time
from typing import List


class RunReporter:
    def __init__(self, language: str = "en"):
        self.language = "zh" if str(language or "").strip().lower() == "zh" else "en"

    def text(self, en: str, zh: str) -> str:
        return zh if self.language == "zh" else en

    def log_final_summary(
        self,
        root_dir: str,
        start_time: float,
        success_count: int,
        failed_tasks: List[str],
        recovered_outputs: List[dict] | None = None,
    ):
        title = self.text(" Processing Summary ", " 处理汇总 ")
        print("\n" + "=" * 20 + title + "=" * 20)
        print(self.text(
            f"Total time: {(time.time() - start_time) / 60:.2f} minutes",
            f"总耗时：{(time.time() - start_time) / 60:.2f} 分钟",
        ))
        print(self.text(f"Successfully extracted: {success_count}", f"成功解压：{success_count}"))

        recovered = list(recovered_outputs or [])
        if recovered:
            print(self.text(f"Partial recoveries: {len(recovered)}", f"部分恢复：{len(recovered)}"))
            for item in recovered:
                archive = os.path.basename(str(item.get("archive") or ""))
                coverage = item.get("archive_coverage") if isinstance(item.get("archive_coverage"), dict) else {}
                completeness = _percent(coverage.get("completeness", item.get("completeness", 0.0)))
                files = _file_coverage(coverage)
                reason = _selection_reason(item)
                print(self.text(
                    f" [partial] {archive}: coverage {completeness}{files}{reason} -> {item.get('out_dir', '')}",
                    f" [partial] {archive}：覆盖度 {completeness}{files}{reason} -> {item.get('out_dir', '')}",
                ))

        if failed_tasks:
            print(self.text(f"Failed tasks: {len(failed_tasks)}", f"失败任务：{len(failed_tasks)}"))
            log_path = os.path.join(root_dir, "failed_log.txt")
            try:
                with open(log_path, "w", encoding="utf-8") as handle:
                    for failed_task in failed_tasks:
                        print(f" [x] {failed_task}")
                        handle.write(f"{failed_task}\n")
                print(self.text(f"Detailed failure list saved to: {log_path}", f"失败详情已保存到：{log_path}"))
            except Exception:
                print(self.text("[ERROR] Failed to save failure log file.", "[ERROR] 保存失败日志文件失败。"))
        else:
            log_path = os.path.join(root_dir, "failed_log.txt")
            try:
                if os.path.exists(log_path):
                    os.remove(log_path)
            except OSError:
                pass
            print(self.text(" [v] All tasks processed successfully!", " [v] 所有任务处理完成！"))

        print("=" * 54)


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
    return f" ({complete}/{matched}/{expected} complete/matched/expected)"


def _selection_reason(item: dict) -> str:
    selected = item.get("selected_attempt") if isinstance(item.get("selected_attempt"), dict) else {}
    vector = selected.get("rank_vector") if isinstance(selected.get("rank_vector"), dict) else {}
    if not vector:
        return ""
    source = vector.get("source") or ""
    decision = selected.get("decision") or ""
    return f" [{decision or 'selected'} via {source or 'verification'}]"
