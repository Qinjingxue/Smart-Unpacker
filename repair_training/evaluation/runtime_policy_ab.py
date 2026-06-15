from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import math
import multiprocessing as mp
import os
import random
import shutil
import sys
import tarfile
import time
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from repair_training.core.material_records import attach_split_volumes as _attach_split_volumes  # noqa: E402
from sunpack.contracts.run_context import RunContext  # noqa: E402
from sunpack.coordinator.extraction_batch import ExtractionBatchRunner  # noqa: E402
from sunpack.coordinator.task_scan import direct_file_task  # noqa: E402
from sunpack.detection import NestedOutputScanPolicy  # noqa: E402
from sunpack.extraction.scheduler import ExtractionScheduler  # noqa: E402
from sunpack.repair.context import zip_route_evidence_flags  # noqa: E402
from sunpack.support.archive_state_view import archive_state_to_bytes  # noqa: E402
from sunpack.support.archive_knowledge_writer import (  # noqa: E402
    commit_task_knowledge,
    ensure_knowledge,
    write_flags,
    write_payload,
)
from repair_training.core.run_layout import (  # noqa: E402
    TMP_ROOT,
    create_evaluation_run_dir,
    latest_training_dataset,
    update_run_manifest,
)


def _dedupe_str(values: Iterable[Any]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "")
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def _materialize_training_archive_state(state: Any, fmt: str) -> Path:
    descriptor = state.to_archive_input_descriptor()
    source = descriptor.to_source_input()
    patches = list(getattr(state, "patches", []) or [])
    if not patches and isinstance(source, dict) and source.get("kind") == "file" and source.get("path"):
        return Path(str(source["path"]))
    data = archive_state_to_bytes(state)
    digest = hashlib.sha256(data).hexdigest()[:24]
    suffix = "." + str(fmt or "archive").lower().lstrip(".")
    root = TMP_ROOT / "materialized_archive_states"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{digest}{suffix}"
    if not path.is_file():
        path.write_bytes(data)
    return path


def _verify_output_against_oracle(path: Path, fmt: str, oracle: dict[str, Any]) -> dict[str, Any]:
    try:
        oracle = oracle if isinstance(oracle, dict) else {}
        expected_bytes = oracle.get("expected_bytes") if isinstance(oracle.get("expected_bytes"), dict) else {}
        if expected_bytes:
            digest = _sha256(path.read_bytes())
            complete = digest == expected_bytes.get("sha256")
            return _label_status(3 if complete else -1, "complete" if complete else "hard_negative", 1.0 if complete else 0.0)
        expected_payload = oracle.get("expected_payload") if isinstance(oracle.get("expected_payload"), dict) else {}
        if expected_payload:
            payload = _decompress_payload(path, fmt)
            digest = _sha256(payload)
            complete = digest == expected_payload.get("sha256")
            completeness = len(payload) / max(1, int(expected_payload.get("size") or len(payload) or 1))
            return _label_status(3 if complete else (1 if completeness > 0 else -1), "complete" if complete else ("partial" if completeness > 0 else "hard_negative"), min(1.0, completeness))
        expected_files = oracle.get("expected_files") if isinstance(oracle.get("expected_files"), dict) else {}
        if expected_files:
            recovered_info = _read_archive_hash_info(path, fmt)
            recovered = recovered_info.get("hashes", {})
            matched = sum(1 for name, meta in expected_files.items() if recovered.get(name) == meta.get("sha256"))
            wrong_overlap = any(name in expected_files and recovered[name] != expected_files[name].get("sha256") for name in recovered)
            wrong_files = sum(1 for name in recovered if name in expected_files and recovered[name] != expected_files[name].get("sha256"))
            unreadable_files = len([name for name in recovered_info.get("entries", []) if name in expected_files and name not in recovered])
            entry_count = len(recovered_info.get("entries", []))
            completeness = matched / max(1, len(expected_files))
            if completeness >= 0.999:
                return {**_label_status(3, "complete", completeness), "matched_files": matched, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
            if wrong_overlap:
                return {**_label_status(-1, "hard_negative", 0.0), "matched_files": matched, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
            if completeness > 0:
                return {**_label_status(1, "partial", completeness), "matched_files": matched, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
            status = "directory_only" if entry_count else "no_progress"
            return {**_label_status(0, status, 0.0), "matched_files": matched, "wrong_files": wrong_files, "unreadable_files": unreadable_files, "entry_count": entry_count, "expected_files": len(expected_files)}
    except Exception as exc:
        return {"status": "hard_negative", "label": -1, "completeness": 0.0, "error": str(exc)}
    return _label_status(0, "no_oracle", 0.0)


def _read_archive_hash_info(path: Path, fmt: str) -> dict[str, Any]:
    normalized = _normalize_format(fmt)
    if normalized == "zip":
        with zipfile.ZipFile(path) as archive:
            entries = [name for name in archive.namelist() if not name.endswith("/")]
            hashes: dict[str, str] = {}
            errors: dict[str, str] = {}
            for name in entries:
                try:
                    hashes[name] = _sha256(archive.read(name))
                except Exception as exc:
                    errors[name] = str(exc)
            return {"entries": entries, "hashes": hashes, "errors": errors}
    if normalized == "tar":
        with tarfile.open(path) as archive:
            return _tar_hash_info_from_archive(archive)
    if normalized in {"tar.gz", "tar.bz2", "tar.xz"}:
        payload = _decompress_payload(path, normalized)
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            return _tar_hash_info_from_archive(archive)
    return {"entries": [], "hashes": {}, "errors": {}}


def _tar_hash_info_from_archive(archive: tarfile.TarFile) -> dict[str, Any]:
    output: dict[str, str] = {}
    entries: list[str] = []
    errors: dict[str, str] = {}
    for item in archive.getmembers():
        if not item.isfile():
            continue
        entries.append(item.name)
        try:
            member = archive.extractfile(item)
            if member is not None:
                output[item.name] = _sha256(member.read())
        except Exception as exc:
            errors[item.name] = str(exc)
    return {"entries": entries, "hashes": output, "errors": errors}


def _decompress_payload(path: Path, fmt: str) -> bytes:
    raw = path.read_bytes()
    normalized = _normalize_format(fmt)
    if normalized in {"gzip", "tar.gz"}:
        return gzip.decompress(raw)
    if normalized in {"bzip2", "tar.bz2"}:
        return bz2.decompress(raw)
    if normalized in {"xz", "tar.xz"}:
        return lzma.decompress(raw)
    return raw


def _normalize_format(fmt: str) -> str:
    value = str(fmt or "").strip().lower().replace("_", ".")
    aliases = {"gz": "gzip", "tgz": "tar.gz", "bz2": "bzip2", "tbz2": "tar.bz2", "txz": "tar.xz"}
    return aliases.get(value, value)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _label_status(label: int, status: str, completeness: float) -> dict[str, Any]:
    return {"label": int(label), "status": status, "completeness": float(completeness)}


PRIORITY_PROFILES = (
    "zip_duplicate_entry_crc_conflict",
    "zip_data_descriptor_cd_conflict",
    "zip_non_utf8_filename_directory_rebuild",
    "zip_sfx_cd_damage",
    "zip_sfx_payload_damage",
    "zip_split_missing_middle_volume",
    "zip_split_tail_volume_truncated",
    "zip_zip64_extra_size_mismatch",
    "zip_extra_field_length_bad",
    "zip_data_descriptor_payload_bad",
)
V3_BASIC_PROFILES = (
    "zip_data_descriptor_payload_bad",
    "zip_data_descriptor_cd_conflict",
    "zip_sfx_payload_damage",
    "zip_sfx_cd_damage",
    "zip_duplicate_entry_crc_conflict",
    "zip_non_utf8_filename_directory_rebuild",
    "zip_zip64_extra_size_mismatch",
    "zip_split_missing_middle_volume",
    "zip_split_tail_volume_truncated",
    "zip_extra_field_length_bad",
    "zip_zip64_eocd_locator_bad",
    "zip_comment_overlap_eocd_shifted",
    "zip_mixed_method_one_entry_bad",
    "zip_wrong_offset_content_overlap",
    "zip_two_step_boundary_then_cd_rebuild",
    "zip_two_step_local_header_then_cd_offset",
    "zip_directory_only_bad_payload",
    "zip_encrypted_payload_bad",
    "zip_encrypted_trailing_junk",
)
V3_COMPOUND_PROFILES = (
    "compound_sfx_cd_offset_payload_partial",
    "compound_sfx_split_descriptor_payload_partial",
    "compound_descriptor_fake_span_flags_cd_offset",
    "compound_zip64_locator_extra_trailing_junk",
    "compound_non_utf8_duplicate_cd_offset",
    "compound_split_sidecar_cd_count_local_header",
    "compound_boundary_drop_cd_payload_bad",
    "compound_comment_eocd_count_cd_rebuild",
    "compound_extra_field_cd_offset_payload_bad",
    "compound_duplicate_descriptor_name_conflict",
    "compound_encrypted_trailing_payload_crc",
)
V3_PHYSICAL_PROFILES = (
    "partial_payload_many_entries_bad",
    "partial_all_entry_payload_damage_with_directory",
    "partial_split_tail_payload_loss",
    "partial_missing_middle_no_sidecar",
    "partial_sfx_payload_loss",
    "partial_wrong_offset_content_overlap_all_bad",
    "partial_rebuild_directory_keeps_bad_payload",
)
V3_PROFILE_GROUPS = {
    "basic": V3_BASIC_PROFILES,
    "compound": V3_COMPOUND_PROFILES,
    "physical": V3_PHYSICAL_PROFILES,
}


@dataclass(frozen=True)
class RunMode:
    name: str
    policy_enabled: bool


@dataclass
class _WorkerSlot:
    worker_id: int
    process: mp.Process
    queue: mp.Queue


RUN_MODES = (
    RunMode("selector_baseline", policy_enabled=False),
    RunMode("zip_model_policy", policy_enabled=True),
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Runtime A/B test for selector/beam fallback versus the ZIP model policy.")
    parser.add_argument("--dataset", default="", help="Runtime graph JSONL used to choose samples. Defaults to the latest canonical ZIP training run.")
    parser.add_argument("--sample-count", type=int, default=12)
    parser.add_argument("--split", choices=("dev", "holdout", "custom"), default="custom", help="Evaluation split. dev defaults to seed 36; holdout defaults to seed 137 and can exclude dev sample IDs.")
    parser.add_argument("--profiles", default="", help="Comma-separated profile filters. Substring matches are accepted.")
    parser.add_argument("--seed", type=int, default=None, help="Sampling seed. Defaults: dev/custom=36, holdout=137.")
    parser.add_argument("--sample-list", default="", help="Optional file containing exact sample IDs to evaluate, one per line. Sampling is skipped except for dataset lookup.")
    parser.add_argument("--exclude-sample-list", default="", help="Optional file containing sample IDs to exclude, one per line. Use dev list when running holdout.")
    parser.add_argument("--write-sample-list", default="", help="Write selected sample IDs to this path. Defaults to reports/<split>_samples.txt.")
    parser.add_argument("--case-timeout-seconds", type=float, default=20.0)
    parser.add_argument("--run-timeout-seconds", type=float, default=0.0, help="Hard wall timeout for one sample/mode run. Defaults to case timeout + 10s.")
    parser.add_argument("--max-rounds", type=int, default=6)
    parser.add_argument("--workers", type=int, default=1, help="Run sample/mode evaluations in parallel processes. 1 preserves serial ordering.")
    parser.add_argument("--parallel-mode", choices=("worker_pool", "per_run_process"), default="worker_pool", help="worker_pool reuses long-lived workers; per_run_process starts a fresh process for each sample/mode.")
    parser.add_argument("--run-dir", default="", help="Evaluation run directory.")
    parser.add_argument("--run-name", default="runtime_policy_ab")
    parser.add_argument("--keep-temp", action="store_true", help="Keep tmp workspace after the report is written.")
    parser.add_argument("--workspace", default="")
    parser.add_argument("--output-json", default="")
    parser.add_argument("--output-jsonl", default="")
    parser.add_argument("--disable-repair-cache", action="store_true")
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--enable-policy-probe", action="store_true", help="Write SUNPACK_REPAIR_POLICY_PROBE_JSONL for each real runtime run.")
    parser.add_argument("--skip-analysis-report", action="store_true", help="Do not write the A/B Markdown/JSON analysis report.")
    args = parser.parse_args()
    if not args.dataset:
        args.dataset = str(latest_training_dataset())
    if args.seed is None:
        args.seed = 137 if args.split == "holdout" else 36

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = create_evaluation_run_dir(args.run_dir or None, run_name=args.run_name)
    report_dir = run_dir / "reports"
    if not args.workspace:
        args.workspace = str(run_dir / "tmp" / "runtime_policy_ab_workspace")
    output_json = Path(args.output_json) if args.output_json else report_dir / f"runtime_policy_ab_{timestamp}.json"
    output_jsonl = Path(args.output_jsonl) if args.output_jsonl else report_dir / f"runtime_policy_ab_{timestamp}.jsonl"
    analysis_json = report_dir / f"runtime_policy_ab_analysis_{timestamp}.json"
    analysis_md = report_dir / f"runtime_policy_ab_analysis_{timestamp}.md"
    sample_list_path = Path(args.write_sample_list) if args.write_sample_list else report_dir / f"{args.split}_samples_{timestamp}.txt"
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    sample_list_path.parent.mkdir(parents=True, exist_ok=True)

    profile_filters = [item.strip() for item in str(args.profiles or "").split(",") if item.strip()]
    exact_sample_ids = _read_sample_id_file(Path(args.sample_list)) if str(args.sample_list or "").strip() else None
    excluded_sample_ids = _read_sample_id_file(Path(args.exclude_sample_list)) if str(args.exclude_sample_list or "").strip() else set()
    records = sample_records(
        Path(args.dataset),
        sample_count=max(1, args.sample_count),
        seed=args.seed,
        profile_filters=profile_filters,
        exact_sample_ids=exact_sample_ids,
        exclude_sample_ids=excluded_sample_ids,
    )
    if not records:
        raise SystemExit("No ZIP samples found for the requested filters.")
    sample_ids = [str(record.get("sample_id") or "") for record in records]
    sample_list_path.write_text("\n".join(sample_ids) + "\n", encoding="utf-8")

    rows: list[dict[str, Any]] = []
    with output_jsonl.open("w", encoding="utf-8") as handle:
        jobs = [(record_index, record, mode) for record_index, record in enumerate(records) for mode in RUN_MODES]
        for row in run_jobs(jobs, args):
            rows.append(row)
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            if args.progress:
                print(
                    f"{row['mode']} {row['sample_id']} {row['terminal_status']} "
                    f"recovery={row['recovery_ratio']:.3f} wall={row['wall_seconds']:.2f}s "
                    f"path={row['repair_module_path']}",
                    flush=True,
                )

    summary = summarize(rows)
    sample_distribution = summarize_sample_distribution(records)
    summary.update({
        "run_dir": str(run_dir),
        "dataset": str(Path(args.dataset)),
        "sample_count": len(records),
        "seed": args.seed,
        "split": args.split,
        "profiles": profile_filters,
        "sample_list": str(sample_list_path),
        "exact_sample_list": str(Path(args.sample_list)) if str(args.sample_list or "").strip() else "",
        "exclude_sample_list": str(Path(args.exclude_sample_list)) if str(args.exclude_sample_list or "").strip() else "",
        "excluded_sample_count": len(excluded_sample_ids),
        "sample_distribution": sample_distribution,
        "output_jsonl": str(output_jsonl),
        "rollout_note": "Both arms call ExtractionBatchRunner.execute(); selector_baseline disables policy and keeps beam enabled, while zip_model_policy enables the production model policy.",
    })
    output_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    analysis_reports: dict[str, str] = {}
    analysis_status = "skipped" if args.skip_analysis_report else "not_started"
    if not args.skip_analysis_report:
        try:
            analysis = build_ab_analysis(summary, rows, records)
            analysis_json.write_text(json.dumps(analysis, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
            analysis_md.write_text(render_ab_analysis_markdown(analysis), encoding="utf-8")
            analysis_reports = {"analysis_json": str(analysis_json), "analysis_md": str(analysis_md)}
            analysis_status = "ok"
        except Exception as exc:
            analysis_status = f"failed:{exc}"
    update_run_manifest(
        run_dir,
        kind="runtime_policy_ab",
        dataset=str(Path(args.dataset)),
        reports={"summary": str(output_json), "rows": str(output_jsonl), **analysis_reports},
        parameters={
            "sample_count": args.sample_count,
            "seed": args.seed,
            "split": args.split,
            "profiles": profile_filters,
            "sample_list": str(sample_list_path),
            "exclude_sample_list": str(Path(args.exclude_sample_list)) if str(args.exclude_sample_list or "").strip() else "",
            "max_rounds": args.max_rounds,
            "workers": args.workers,
            "sample_distribution": sample_distribution,
        },
        analysis_report_status=analysis_status,
        ended_at=datetime.now().isoformat(timespec="seconds"),
    )
    if not args.keep_temp:
        shutil.rmtree(run_dir / "tmp", ignore_errors=True)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def run_jobs(jobs: list[tuple[int, dict[str, Any], RunMode]], args: argparse.Namespace) -> Iterable[dict[str, Any]]:
    workers = max(1, int(getattr(args, "workers", 1) or 1))
    timeout = _run_timeout_seconds(args)
    parallel_mode = str(getattr(args, "parallel_mode", "worker_pool") or "worker_pool")
    if parallel_mode == "worker_pool":
        yield from run_jobs_worker_pool(jobs, args, workers=workers, timeout_seconds=timeout)
        return
    yield from run_jobs_per_run_process(jobs, args, workers=workers, timeout_seconds=timeout)


def run_jobs_per_run_process(
    jobs: list[tuple[int, dict[str, Any], RunMode]],
    args: argparse.Namespace,
    *,
    workers: int,
    timeout_seconds: float,
) -> Iterable[dict[str, Any]]:
    if workers <= 1:
        for record_index, record, mode in jobs:
            yield run_one_with_timeout(record, mode, args, record_index=record_index, timeout_seconds=timeout_seconds)
        return
    pending = list(jobs)
    active: list[dict[str, Any]] = []
    while pending or active:
        while pending and len(active) < workers:
            record_index, record, mode = pending.pop(0)
            queue: mp.Queue = mp.Queue(maxsize=1)
            proc = mp.Process(
                target=_run_one_child,
                args=(record, mode, args, record_index, queue),
                daemon=True,
            )
            proc.start()
            active.append({
                "process": proc,
                "queue": queue,
                "started": time.perf_counter(),
                "record": record,
                "mode": mode,
                "record_index": record_index,
            })
        for item in list(active):
            proc = item["process"]
            queue = item["queue"]
            if not queue.empty():
                row = queue.get()
                proc.join(timeout=1)
                active.remove(item)
                yield row
                continue
            if proc.is_alive() and time.perf_counter() - float(item["started"]) > timeout_seconds:
                proc.terminate()
                proc.join(timeout=3)
                active.remove(item)
                yield timeout_row(
                    item["record"],
                    item["mode"],
                    item["record_index"],
                    timeout_seconds=timeout_seconds,
                    reason="hard_run_timeout",
                    workspace_root=str(getattr(args, "workspace", "")),
                )
                continue
            if not proc.is_alive():
                proc.join(timeout=1)
                active.remove(item)
                yield timeout_row(
                    item["record"],
                    item["mode"],
                    item["record_index"],
                    timeout_seconds=min(timeout_seconds, time.perf_counter() - float(item["started"])),
                    reason="worker_exited_without_result",
                    workspace_root=str(getattr(args, "workspace", "")),
                )
        if active:
            time.sleep(0.05)


def run_jobs_worker_pool(
    jobs: list[tuple[int, dict[str, Any], RunMode]],
    args: argparse.Namespace,
    *,
    workers: int,
    timeout_seconds: float,
) -> Iterable[dict[str, Any]]:
    if not jobs:
        return
    pending: list[tuple[int, int, dict[str, Any], RunMode]] = [
        (job_id, record_index, record, mode)
        for job_id, (record_index, record, mode) in enumerate(jobs)
    ]
    result_q: mp.Queue = mp.Queue()
    slots: dict[int, _WorkerSlot] = {}
    active: dict[int, dict[str, Any]] = {}
    next_worker_id = 0
    completed = 0
    total = len(pending)

    def start_worker() -> _WorkerSlot:
        nonlocal next_worker_id
        worker_id = next_worker_id
        next_worker_id += 1
        input_q: mp.Queue = mp.Queue(maxsize=1)
        process = mp.Process(
            target=_runtime_ab_worker_loop,
            args=(worker_id, input_q, result_q, args),
            daemon=True,
        )
        process.start()
        slot = _WorkerSlot(worker_id=worker_id, process=process, queue=input_q)
        slots[worker_id] = slot
        return slot

    def assign(slot: _WorkerSlot) -> None:
        if not pending:
            try:
                slot.queue.put(None)
            except Exception:
                pass
            return
        job_id, record_index, record, mode = pending.pop(0)
        active[slot.worker_id] = {
            "job_id": job_id,
            "record_index": record_index,
            "record": record,
            "mode": mode,
            "started": time.perf_counter(),
        }
        slot.queue.put((job_id, record_index, record, mode))

    for _ in range(max(1, min(workers, total))):
        assign(start_worker())

    try:
        while completed < total:
            try:
                message = result_q.get(timeout=0.05)
            except Exception:
                message = None
            if isinstance(message, dict):
                worker_id = int(message.get("worker_id", -1))
                current = active.pop(worker_id, None)
                if current is not None:
                    completed += 1
                    row = message.get("row")
                    if not isinstance(row, dict):
                        row = timeout_row(
                            current["record"],
                            current["mode"],
                            current["record_index"],
                            timeout_seconds=time.perf_counter() - float(current["started"]),
                            reason=str(message.get("reason") or "worker_returned_no_row"),
                            workspace_root=str(getattr(args, "workspace", "")),
                        )
                    yield row
                slot = slots.get(worker_id)
                if slot is not None and slot.process.is_alive():
                    assign(slot)

            for worker_id, current in list(active.items()):
                slot = slots.get(worker_id)
                process = slot.process if slot is not None else None
                elapsed = time.perf_counter() - float(current["started"])
                if process is not None and process.is_alive() and elapsed <= timeout_seconds:
                    continue
                if process is not None and process.is_alive():
                    process.terminate()
                    process.join(timeout=3)
                    reason = "hard_run_timeout"
                    wall = timeout_seconds
                else:
                    reason = "worker_exited_without_result"
                    wall = min(timeout_seconds, elapsed)
                active.pop(worker_id, None)
                slots.pop(worker_id, None)
                completed += 1
                yield timeout_row(
                    current["record"],
                    current["mode"],
                    current["record_index"],
                    timeout_seconds=wall,
                    reason=reason,
                    workspace_root=str(getattr(args, "workspace", "")),
                )
                if pending:
                    assign(start_worker())

            for worker_id, slot in list(slots.items()):
                if worker_id in active:
                    continue
                if not slot.process.is_alive():
                    slot.process.join(timeout=1)
                    slots.pop(worker_id, None)
            if not active and not pending and completed >= total:
                break
    finally:
        for slot in list(slots.values()):
            if slot.process.is_alive():
                try:
                    slot.queue.put(None)
                except Exception:
                    pass
                slot.process.join(timeout=1)
            if slot.process.is_alive():
                slot.process.terminate()
                slot.process.join(timeout=3)


def run_one_with_timeout(
    record: dict[str, Any],
    mode: RunMode,
    args: argparse.Namespace,
    *,
    record_index: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    queue: mp.Queue = mp.Queue(maxsize=1)
    proc = mp.Process(target=_run_one_child, args=(record, mode, args, record_index, queue), daemon=True)
    started = time.perf_counter()
    proc.start()
    proc.join(timeout=max(0.1, timeout_seconds))
    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=3)
        return timeout_row(record, mode, record_index, timeout_seconds=timeout_seconds, reason="hard_run_timeout", workspace_root=str(getattr(args, "workspace", "")))
    if not queue.empty():
        return queue.get()
    return timeout_row(
        record,
        mode,
        record_index,
        timeout_seconds=time.perf_counter() - started,
        reason="worker_exited_without_result",
        workspace_root=str(getattr(args, "workspace", "")),
    )


def _run_one_child(record: dict[str, Any], mode: RunMode, args: argparse.Namespace, record_index: int, queue: mp.Queue) -> None:
    try:
        queue.put(run_one(record, mode, args, record_index=record_index))
    except Exception as exc:
        queue.put(timeout_row(record, mode, record_index, timeout_seconds=0.0, reason=f"exception:{exc}", workspace_root=str(getattr(args, "workspace", ""))))


def _runtime_ab_worker_loop(worker_id: int, input_q: mp.Queue, result_q: mp.Queue, args: argparse.Namespace) -> None:
    while True:
        item = input_q.get()
        if item is None:
            return
        job_id, record_index, record, mode = item
        try:
            row = run_one(record, mode, args, record_index=record_index)
            row["worker_id"] = worker_id
            row["worker_reused"] = True
            result_q.put({"worker_id": worker_id, "job_id": job_id, "row": row})
        except Exception as exc:
            result_q.put({
                "worker_id": worker_id,
                "job_id": job_id,
                "row": timeout_row(
                    record,
                    mode,
                    record_index,
                    timeout_seconds=0.0,
                    reason=f"exception:{exc}",
                    workspace_root=str(getattr(args, "workspace", "")),
                ),
            })


def _run_timeout_seconds(args: argparse.Namespace) -> float:
    configured = float(getattr(args, "run_timeout_seconds", 0.0) or 0.0)
    if configured > 0:
        return configured
    return max(10.0, float(getattr(args, "case_timeout_seconds", 20.0) or 20.0) + 10.0)


def timeout_row(
    record: dict[str, Any],
    mode: RunMode,
    record_index: int,
    *,
    timeout_seconds: float,
    reason: str,
    workspace_root: str = "",
) -> dict[str, Any]:
    sample_id = str(record.get("sample_id") or f"sample_{record_index}")
    profile = damage_profile(record)
    layer = profile_layer(record)
    workspace = Path(workspace_root) if workspace_root else TMP_ROOT / "runtime_policy_ab_workspace"
    return {
        "sample_id": sample_id,
        "damage_profile": profile,
        "profile_layer": layer,
        "physical_complete_expected": physical_complete_expected(record),
        "mode": mode.name,
        "complete": False,
        "partial": False,
        "recovery_ratio": 0.0,
        "best_status": "",
        "terminal_status": "timeout",
        "terminal_reason": reason,
        "verification_status": "",
        "repair_module_path": [],
        "repair_action_path": [],
        "policy_initial_status": "",
        "policy_selected_count": 0,
        "policy_fallback_count": 0,
        "policy_abstain_by_reason": {},
        "fallback_selected_candidate_ids": [],
        "fallback_candidate_in_request_count": 0,
        "beam_used_count": 0,
        "round_count": 0,
        "wall_seconds": round(float(timeout_seconds), 4),
        "candidate_count": 0,
        "first_round_candidates": [],
        "round_candidate_lists": [],
        "final_archive_path": "",
        "final_source_kind": "",
        "output_dirs": [],
        "trace_path": str(workspace / mode.name / _safe_name(sample_id) / "repair_trace.jsonl"),
        "probe_path": str(workspace / mode.name / _safe_name(sample_id) / "policy_probe.jsonl"),
        "probe_event_count": 0,
        "policy_probe_request_count": 0,
        "phase_timings": {},
        "run_timeout_reason": reason,
    }


def sample_records(
    dataset: Path,
    *,
    sample_count: int,
    seed: int,
    profile_filters: list[str] | None = None,
    exact_sample_ids: list[str] | None = None,
    exclude_sample_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    profile_filters = profile_filters or []
    exact_sample_id_list = [str(item).strip() for item in (exact_sample_ids or []) if str(item).strip()]
    exact_sample_id_set = set(exact_sample_id_list) or None
    exclude_sample_ids = {str(item).strip() for item in (exclude_sample_ids or set()) if str(item).strip()}
    rng = random.Random(seed)
    by_profile: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_group_profile: dict[str, dict[str, list[dict[str, Any]]]] = {
        group: defaultdict(list) for group in V3_PROFILE_GROUPS
    }
    fallback: list[dict[str, Any]] = []
    seen: set[str] = set()
    target_profiles = profile_filters or list(PRIORITY_PROFILES)
    full_scan = bool(profile_filters)
    unique_scan_limit = None if full_scan else max(1000, sample_count * 60)

    for row in _iter_unique_rows(dataset):
        sample_id = str(row.get("sample_id") or "")
        if not sample_id or sample_id in seen:
            continue
        if sample_id in exclude_sample_ids:
            continue
        if exact_sample_id_set is not None and sample_id not in exact_sample_id_set:
            continue
        record = _load_record(row)
        damaged_path = str((record.get("damaged_input") or {}).get("path") or record.get("damaged_path") or "")
        if not damaged_path or not Path(damaged_path).is_file():
            continue
        seen.add(sample_id)
        profile = damage_profile(record)
        if profile_filters and not _matches_any(profile, profile_filters):
            continue
        if any(_matches(profile, wanted) for wanted in target_profiles):
            by_profile[profile].append(record)
        group = v3_profile_group(record)
        if group in by_group_profile:
            by_group_profile[group][profile].append(record)
        fallback.append(record)
        if unique_scan_limit and len(seen) >= unique_scan_limit:
            break

    if exact_sample_id_set is not None:
        exact_records = [record for record in fallback if str(record.get("sample_id") or "") in exact_sample_id_set]
        order = {sample_id: index for index, sample_id in enumerate(exact_sample_id_list)}
        exact_records.sort(key=lambda record: order.get(str(record.get("sample_id") or ""), 10**9))
        return exact_records[:sample_count]

    selected: list[dict[str, Any]] = []
    if not profile_filters:
        quotas = _default_v3_sample_quotas(sample_count)
        for group, quota in quotas.items():
            selected.extend(_select_stratified_profiles(by_group_profile[group], quota, rng, selected))
        if len(selected) < sample_count:
            remaining = [record for record in fallback if str(record.get("sample_id")) not in {str(item.get("sample_id")) for item in selected}]
            rng.shuffle(remaining)
            selected.extend(remaining[: sample_count - len(selected)])
    elif target_profiles:
        per_bucket = max(1, math.ceil(sample_count / max(1, len(target_profiles))))
        for wanted in target_profiles:
            bucket = [record for profile, records in by_profile.items() if _matches(profile, wanted) for record in records]
            rng.shuffle(bucket)
            selected.extend(bucket[:per_bucket])
            if len(selected) >= sample_count:
                break
    if len(selected) < sample_count:
        remaining = [record for record in fallback if str(record.get("sample_id")) not in {str(item.get("sample_id")) for item in selected}]
        rng.shuffle(remaining)
        selected.extend(remaining[: sample_count - len(selected)])
    rng.shuffle(selected)
    return selected[:sample_count]


def _read_sample_id_file(path: Path) -> list[str]:
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.is_file():
        raise SystemExit(f"sample id list does not exist: {path}")
    sample_ids: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        sample_id = text.split()[0]
        if sample_id not in seen:
            seen.add(sample_id)
            sample_ids.append(sample_id)
    return sample_ids


def _default_v3_sample_quotas(sample_count: int) -> dict[str, int]:
    total = max(1, int(sample_count))
    physical = max(1, int(round(total * 0.25)))
    compound = max(1, int(round(total * 0.40)))
    basic = max(0, total - physical - compound)
    return {"basic": basic, "compound": compound, "physical": physical}


def _select_stratified_profiles(
    by_profile: dict[str, list[dict[str, Any]]],
    quota: int,
    rng: random.Random,
    already_selected: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if quota <= 0 or not by_profile:
        return []
    selected_ids = {str(item.get("sample_id") or "") for item in already_selected}
    profiles = sorted(by_profile)
    buckets: dict[str, list[dict[str, Any]]] = {}
    for profile in profiles:
        bucket = [record for record in by_profile[profile] if str(record.get("sample_id") or "") not in selected_ids]
        rng.shuffle(bucket)
        if bucket:
            buckets[profile] = bucket
    output: list[dict[str, Any]] = []
    while len(output) < quota and buckets:
        progressed = False
        for profile in list(buckets):
            bucket = buckets.get(profile) or []
            if not bucket:
                buckets.pop(profile, None)
                continue
            output.append(bucket.pop())
            progressed = True
            if not bucket:
                buckets.pop(profile, None)
            if len(output) >= quota:
                break
        if not progressed:
            break
    return output


def run_one(record: dict[str, Any], mode: RunMode, args: argparse.Namespace, *, record_index: int) -> dict[str, Any]:
    started = time.perf_counter()
    phase_timings: dict[str, float] = {}
    phase_started = time.perf_counter()
    sample_id = _safe_name(str(record.get("sample_id") or f"sample_{record_index}"))
    record = prepare_record(record)
    fmt = str(record.get("format") or record.get("material_format") or "zip")
    phase_timings["prepare_record"] = round(time.perf_counter() - phase_started, 4)
    phase_started = time.perf_counter()
    workspace = Path(args.workspace) / mode.name / sample_id
    output_root = workspace / "outputs"
    repair_workspace = workspace / "repair"
    trace_path = workspace / "repair_trace.jsonl"
    probe_path = workspace / "policy_probe.jsonl"
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    output_root.mkdir(parents=True, exist_ok=True)
    repair_workspace.mkdir(parents=True, exist_ok=True)
    phase_timings["workspace_setup"] = round(time.perf_counter() - phase_started, 4)
    phase_started = time.perf_counter()

    config = runtime_config(
        mode,
        workspace=repair_workspace,
        output_root=output_root,
        max_rounds=max(1, int(args.max_rounds or 1)),
        case_timeout_seconds=max(1.0, float(args.case_timeout_seconds or 30.0)),
        disable_repair_cache=bool(args.disable_repair_cache),
    )
    task = task_from_record(record)
    phase_timings["task_build"] = round(time.perf_counter() - phase_started, 4)
    phase_started = time.perf_counter()
    policy_initial_status = policy_status_for_task(config, task)
    phase_timings["policy_status"] = round(time.perf_counter() - phase_started, 4)
    previous_trace = os.environ.get("SUNPACK_REPAIR_TRACE_JSONL")
    previous_probe = os.environ.get("SUNPACK_REPAIR_POLICY_PROBE_JSONL")
    previous_probe_run_id = os.environ.get("SUNPACK_REPAIR_POLICY_PROBE_RUN_ID")
    os.environ["SUNPACK_REPAIR_TRACE_JSONL"] = str(trace_path)
    if bool(getattr(args, "enable_policy_probe", False)):
        os.environ["SUNPACK_REPAIR_POLICY_PROBE_JSONL"] = str(probe_path)
        os.environ["SUNPACK_REPAIR_POLICY_PROBE_RUN_ID"] = f"{sample_id}:{mode.name}"
    terminal_status = "unknown"
    terminal_reason = ""
    output_dirs: list[str] = []
    try:
        phase_started = time.perf_counter()
        runner = ExtractionBatchRunner(
            RunContext(),
            ExtractionScheduler(
                max_retries=1,
                process_config={"max_seconds": max(1.0, float(args.case_timeout_seconds or 30.0))},
                output_config={"root": str(output_root)},
                extraction_config={"write_progress_manifest": True},
            ),
            NestedOutputScanPolicy(config),
            config=config,
        )
        phase_timings["runner_init"] = round(time.perf_counter() - phase_started, 4)
        phase_started = time.perf_counter()
        output_dirs = list(runner.execute([task]) or [])
        phase_timings["runner_execute"] = round(time.perf_counter() - phase_started, 4)
        terminal_status = "completed"
    except Exception as exc:
        terminal_status = "exception"
        terminal_reason = str(exc)
    finally:
        if previous_trace is None:
            os.environ.pop("SUNPACK_REPAIR_TRACE_JSONL", None)
        else:
            os.environ["SUNPACK_REPAIR_TRACE_JSONL"] = previous_trace
        if previous_probe is None:
            os.environ.pop("SUNPACK_REPAIR_POLICY_PROBE_JSONL", None)
        else:
            os.environ["SUNPACK_REPAIR_POLICY_PROBE_JSONL"] = previous_probe
        if previous_probe_run_id is None:
            os.environ.pop("SUNPACK_REPAIR_POLICY_PROBE_RUN_ID", None)
        else:
            os.environ["SUNPACK_REPAIR_POLICY_PROBE_RUN_ID"] = previous_probe_run_id

    phase_started = time.perf_counter()
    trace_events = read_jsonl(trace_path)
    probe_events = read_jsonl(probe_path)
    candidate_log = list(task.fact_bag.get("repair.candidate_log") or [])
    trace_summary = summarize_trace(trace_events, candidate_log, policy_enabled=mode.policy_enabled)
    phase_timings["trace_summary"] = round(time.perf_counter() - phase_started, 4)
    phase_started = time.perf_counter()
    final_archive_path, final_source_kind = final_archive_source(task, record, fmt)
    label_info = _verify_output_against_oracle(Path(final_archive_path), fmt, record.get("oracle") if isinstance(record.get("oracle"), dict) else {}) if final_archive_path else {"status": "missing_output", "label": 0, "completeness": 0.0}
    phase_timings["oracle_verify"] = round(time.perf_counter() - phase_started, 4)
    recovery = float(label_info.get("completeness", 0.0) or 0.0)
    if recovery >= 0.999 or str(label_info.get("status") or "") == "complete":
        terminal_status = "complete"
    elif terminal_status == "completed" and recovery > 0:
        terminal_status = "partial"
    elif terminal_status == "completed" and task.fact_bag.get("repair.last_result"):
        terminal_status = "unrepairable"
    elif terminal_status == "completed":
        terminal_status = "failed"
    wall = time.perf_counter() - started
    return {
        "sample_id": record.get("sample_id"),
        "damage_profile": damage_profile(record),
        "profile_layer": profile_layer(record),
        "physical_complete_expected": physical_complete_expected(record),
        "mode": mode.name,
        "complete": recovery >= 0.999 or terminal_status == "complete",
        "partial": 0.0 < recovery < 0.999,
        "recovery_ratio": round(recovery, 6),
        "best_status": str(label_info.get("status") or ""),
        "terminal_status": terminal_status,
        "terminal_reason": terminal_reason,
        "verification_status": str(label_info.get("status") or ""),
        "repair_module_path": trace_summary["repair_module_path"],
        "repair_action_path": trace_summary["repair_action_path"],
        "policy_initial_status": policy_initial_status,
        "policy_selected_count": trace_summary["policy_selected_count"],
        "policy_fallback_count": trace_summary["policy_fallback_count"],
        "policy_abstain_by_reason": trace_summary["policy_abstain_by_reason"],
        "fallback_selected_candidate_ids": trace_summary["fallback_selected_candidate_ids"],
        "fallback_candidate_in_request_count": trace_summary["fallback_candidate_in_request_count"],
        "beam_used_count": trace_summary["beam_used_count"],
        "round_count": trace_summary["round_count"],
        "wall_seconds": round(wall, 4),
        "candidate_count": trace_summary["candidate_count"],
        "first_round_candidates": trace_summary["round_candidate_lists"][0] if trace_summary["round_candidate_lists"] else [],
        "round_candidate_lists": trace_summary["round_candidate_lists"],
        "final_archive_path": final_archive_path,
        "final_source_kind": final_source_kind,
        "output_dirs": output_dirs,
        "trace_path": str(trace_path),
        "probe_path": str(probe_path),
        "probe_event_count": len(probe_events),
        "policy_probe_request_count": sum(1 for item in probe_events if item.get("event") == "policy_probe_request"),
        "phase_timings": phase_timings,
    }


def runtime_config(
    mode: RunMode,
    *,
    workspace: Path,
    output_root: Path,
    max_rounds: int,
    case_timeout_seconds: float = 30.0,
    disable_repair_cache: bool,
) -> dict[str, Any]:
    repair_seconds = max(5.0, min(120.0, float(case_timeout_seconds)))
    return {
        "repair": {
            "enabled": True,
            "workspace": str(workspace),
            "max_repair_rounds_per_task": max_rounds,
            "max_attempts_per_task": max_rounds,
            "max_repair_seconds_per_task": repair_seconds,
            "runtime_cache": {"enabled": not bool(disable_repair_cache), "max_entries": 512},
            "module_limits": {
                "max_candidates_per_module": 6,
                "verify_candidates": False,
                "max_seconds_per_module": 8.0,
                "max_stream_trim_probe_attempts": 8,
                "max_stream_trim_decode_mb": 32,
            },
            "beam": {
                "enabled": True,
                "beam_width": 6,
                "max_candidates_per_state": 8,
                "max_analyze_candidates": 24,
                "max_assess_candidates": 12,
                "max_rounds": max_rounds,
                "min_improvement": 0.01,
                "patience_rounds": 3,
                "return_best_partial": True,
            },
            "policy": {
                "enabled": bool(mode.policy_enabled),
                "strict_provider_errors": False,
            },
        },
        "verification": {
            "enabled": True,
            "methods": [{"name": "archive_test_crc"}],
            "max_retries": 0,
            "retry_on_verification_failure": True,
            "cleanup_failed_output": False,
            "accept_partial_when_source_damaged": True,
            "partial_accept_threshold": 0.2,
            "complete_accept_threshold": 0.999,
            "recovery_min_improvement": 0.01,
        },
        "output": {"root": str(output_root)},
        "extraction": {"write_progress_manifest": True},
        "performance": {
            "scheduler_profile": "single",
            "parallel_preflight_inspect": False,
            "parallel_resource_preflight": False,
        },
    }


def task_from_record(record: dict[str, Any]):
    damaged_path = str(record.get("damaged_path") or (record.get("damaged_input") or {}).get("path") or "")
    if not damaged_path or not Path(damaged_path).is_file():
        raise FileNotFoundError(f"damaged archive path is missing or invalid for sample {record.get('sample_id')}: {damaged_path}")
    task = direct_file_task(damaged_path)
    _attach_split_to_task(task, record)
    _write_runtime_ab_record_knowledge(task, record)
    task.fact_bag.set("analysis.selected_format", "zip")
    task.fact_bag.set("analysis.status", "selected")
    task.fact_bag.set("analysis.prepass", {
        "status": "selected",
        "format": "zip",
        "selected_format": "zip",
        "confidence": 0.82,
        "zip_structure_features": record.get("zip_structure_features") or {},
        "zip_container_tags": record.get("zip_container_tags") or [],
        "damage_profile": damage_profile(record),
    })
    task.fact_bag.set("analysis.fuzzy", {"binary_profile": {"status": "selected", "archive_type": "zip", "confidence": 0.82}})
    task.fact_bag.set("analysis.evidences", [{
        "format": "zip",
        "confidence": 0.82,
        "status": "selected",
        "segments": [{
            "start_offset": 0,
            "end_offset": None,
            "confidence": 0.82,
            "role": "primary",
            "damage_flags": list(record.get("runtime_damage_flags") or record.get("damage_flags") or []),
            "evidence": list(record.get("route_evidence_flags") or []),
        }],
        "details": {
            "zip_structure_features": record.get("zip_structure_features") or {},
            "zip_container_tags": record.get("zip_container_tags") or [],
            "damage_profile": damage_profile(record),
        },
    }])
    task.fact_bag.set("archive.format_hint", "zip")
    task.fact_bag.set("repair_training.damage_profile", damage_profile(record))
    task.fact_bag.set("repair_training.sample_id", record.get("sample_id"))
    task.fact_bag.set("repair_training.zip_structure_features", record.get("zip_structure_features") or {})
    task.fact_bag.set("repair_training.zip_container_tags", record.get("zip_container_tags") or [])
    task.ensure_archive_state()
    return task


def _write_runtime_ab_record_knowledge(task: Any, record: dict[str, Any]) -> None:
    structure = dict(record.get("zip_structure_features") or {})
    tags = [str(item) for item in record.get("zip_container_tags") or [] if str(item)]
    profile = damage_profile(record)
    source_derivation = dict(record.get("source_derivation") or {})
    if structure:
        source_derivation.setdefault("zip_structure_features", structure)
    if tags:
        source_derivation.setdefault("zip_container_tags", tags)
    if profile:
        source_derivation.setdefault("damage_profile", profile)
    route_flags = zip_route_evidence_flags({
        "format": "zip",
        "source_input": record.get("damaged_input") or {},
        "zip_structure_features": structure,
        "zip_container_tags": tags,
        "damage_profile": profile,
        "source_derivation": source_derivation,
        "damage_flags": list(record.get("runtime_damage_flags") or record.get("damage_flags") or []),
    })
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "analysis.summary",
        {"format": "zip", "status": "selected", "confidence": 0.82},
        source_layer="evaluation",
        source_module="runtime_policy_ab",
    )
    write_payload(
        knowledge,
        "analysis",
        {
            "selected_format": "zip",
            "status": "selected",
            "prepass": {
                "status": "selected",
                "format": "zip",
                "selected_format": "zip",
                "confidence": 0.82,
                "zip_structure_features": structure,
                "zip_container_tags": tags,
                "damage_profile": profile,
                "route_evidence_flags": route_flags,
            },
            "fuzzy": {"binary_profile": {"status": "selected", "archive_type": "zip", "confidence": 0.82}},
            "evidences": [{
                "format": "zip",
                "confidence": 0.82,
                "status": "selected",
                "segments": [{
                    "start_offset": 0,
                    "end_offset": None,
                    "confidence": 0.82,
                    "role": "primary",
                    "damage_flags": list(record.get("runtime_damage_flags") or record.get("damage_flags") or []),
                    "evidence": route_flags,
                }],
                "details": {
                    "zip_structure_features": structure,
                    "zip_container_tags": tags,
                    "damage_profile": profile,
                    "route_evidence_flags": route_flags,
                },
            }],
        },
        source_layer="evaluation",
        source_module="runtime_policy_ab",
    )
    write_payload(
        knowledge,
        "format.zip",
        {
            "structure": structure,
            "container_tags": tags,
            "route_evidence_flags": route_flags,
        },
        source_layer="evaluation",
        source_module="runtime_policy_ab",
        confidence=0.82,
    )
    if route_flags:
        write_flags(
            knowledge,
            "format.zip.route_evidence",
            route_flags,
            source_layer="evaluation",
            source_module="runtime_policy_ab",
            confidence=0.82,
        )
    write_payload(
        knowledge,
        "source",
        {"derivation": source_derivation, "profile": profile},
        source_layer="evaluation",
        source_module="runtime_policy_ab",
    )
    write_payload(
        knowledge,
        "training",
        {"damage_profile": profile, "sample_id": str(record.get("sample_id") or "")},
        source_layer="evaluation",
        source_module="runtime_policy_ab",
    )
    commit_task_knowledge(task, knowledge)


def _attach_split_to_task(task: Any, record: dict[str, Any]) -> None:
    source_input = dict(record.get("damaged_input") or {})
    _attach_split_volumes(source_input, record)
    part_items = [
        dict(item)
        for item in source_input.get("parts") or []
        if isinstance(item, dict) and item.get("path")
    ]
    parts = _dedupe_str([str(item.get("path") or "") for item in part_items])
    main_path = str(task.main_path)
    if main_path and main_path not in parts and not bool(source_input.get("use_parts_only")):
        parts.append(main_path)
        part_items.append({"path": main_path, "start": 0, "end": None, "role": "main"})
    if len(parts) <= 1:
        return
    task.all_parts = parts
    task.split_info.parts = parts
    task.split_info.is_split = True
    task.split_info.source = "repair_training_runtime_ab"
    task.split_info.volumes = [{"path": path, "role": "volume"} for path in parts]
    task.fact_bag.set("candidate.member_paths", parts)
    task.fact_bag.set("file.split_members", [path for path in parts if path != main_path])
    task.fact_bag.set("relation.is_split_related", True)
    task.fact_bag.set("relation.split_group_complete", True)
    task.fact_bag.set("relation.split_volumes", list(task.split_info.volumes))
    ranges: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in part_items:
        path = str(item.get("path") or "")
        if not path or path in seen:
            continue
        seen.add(path)
        ranges.append({"path": path, "start": int(item.get("start") or 0), "end": item.get("end")})
    if ranges:
        task.set_archive_input({
            "kind": "concat_ranges",
            "ranges": ranges,
            "format_hint": "zip",
            "path": main_path,
            "parts": part_items,
            "use_parts_only": bool(source_input.get("use_parts_only")),
        })


def policy_status_for_task(config: dict[str, Any], task: Any) -> str:
    try:
        from sunpack.coordinator.repair_stage import ArchiveRepairStage
        from sunpack.extraction.result import ExtractionResult
        from sunpack.verification.result import ArchiveCoverageSummary, VerificationResult

        stage = ArchiveRepairStage(config)
        coverage = ArchiveCoverageSummary(completeness=0.0, file_coverage=0.0, expected_files=0, confidence=1.0)
        verification = VerificationResult(
            completeness=0.0,
            recoverable_upper_bound=1.0,
            assessment_status="unusable",
            source_integrity="damaged",
            decision_hint="repair",
            archive_coverage=coverage,
        )
        result = ExtractionResult(success=False, archive=task.main_path, out_dir="", all_parts=task.all_parts, error="status probe")
        return "active" if stage.policy_active_for_verification(task, result, verification) else str(stage.scheduler.policy_manager.status_for_job(stage._job_from_verification_assessment(task, result, verification)).get("decision_status") or "inactive")
    except Exception as exc:
        return f"status_error:{exc}"


def final_archive_source(task: Any, record: dict[str, Any], fmt: str) -> tuple[str, str]:
    try:
        state = task.archive_state()
        try:
            path = _materialize_training_archive_state(state, fmt)
            return str(path), "archive_state"
        except Exception:
            source = state.to_archive_input_descriptor().to_source_input()
            if isinstance(source, dict) and source.get("path"):
                return str(source.get("path")), str(source.get("kind") or "file")
    except Exception:
        pass
    path = str((record.get("damaged_input") or {}).get("path") or record.get("damaged_path") or "")
    return path, "damaged_input"


def summarize_trace(events: list[dict[str, Any]], candidate_log: list[Any], *, policy_enabled: bool) -> dict[str, Any]:
    module_path: list[str] = []
    action_path: list[str] = []
    candidate_count = 0
    policy_selected = 0
    policy_fallback = 0
    policy_abstain_reasons: Counter[str] = Counter()
    fallback_selected_candidate_ids: list[str] = []
    fallback_candidate_in_request = 0
    round_candidate_lists: list[list[dict[str, Any]]] = []
    for event in events:
        event_name = str(event.get("event") or "")
        if event_name == "repair_candidates_generated":
            candidate_count += int(event.get("candidate_count", 0) or 0)
            candidates = event.get("candidates") if isinstance(event.get("candidates"), list) else []
            if candidates:
                round_candidate_lists.append([_compact_candidate(item) for item in candidates if isinstance(item, dict)][:20])
        if event_name != "repair_selected_result":
            continue
        result = event.get("result") if isinstance(event.get("result"), dict) else {}
        module = str(result.get("module_name") or "")
        if module:
            module_path.append(module)
        action_path.extend(str(item) for item in result.get("actions") or [] if str(item))
        selection = event.get("selection") if isinstance(event.get("selection"), dict) else {}
        policy = selection.get("policy") if isinstance(selection.get("policy"), dict) else {}
        if str(policy.get("decision_status") or "") == "selected":
            policy_selected += 1
        elif policy_enabled and (selection.get("policy_fallback") or policy):
            policy_fallback += 1
            reason = str(policy.get("fallback_reason") or policy.get("invalid_candidate_id_reason") or "fallback")
            if reason:
                policy_abstain_reasons[reason] += 1
            fallback_id = str(selection.get("fallback_selected_candidate_id") or policy.get("fallback_selected_candidate_id") or "")
            if fallback_id:
                fallback_selected_candidate_ids.append(fallback_id)
            if bool(selection.get("fallback_candidate_in_request") or policy.get("fallback_candidate_in_request")):
                fallback_candidate_in_request += 1
        candidates = selection.get("candidates") if isinstance(selection.get("candidates"), list) else []
        if candidates:
            round_candidate_lists.append([_compact_candidate(item) for item in candidates if isinstance(item, dict)][:20])
    for entry in candidate_log:
        if not isinstance(entry, dict):
            continue
        if _candidate_log_selected(entry):
            candidate = entry.get("candidate") if isinstance(entry.get("candidate"), dict) else {}
            module = str(candidate.get("module_name") or candidate.get("module") or "")
            if module and module not in module_path:
                module_path.append(module)
    beam_used = sum(1 for entry in candidate_log if isinstance(entry, dict) and str(entry.get("phase") or "").startswith("beam"))
    return {
        "repair_module_path": module_path,
        "repair_action_path": action_path,
        "policy_selected_count": policy_selected,
        "policy_fallback_count": policy_fallback,
        "policy_abstain_by_reason": dict(sorted(policy_abstain_reasons.items())),
        "fallback_selected_candidate_ids": fallback_selected_candidate_ids,
        "fallback_candidate_in_request_count": fallback_candidate_in_request,
        "beam_used_count": beam_used,
        "round_count": max(len(module_path), policy_selected + policy_fallback, beam_used),
        "candidate_count": candidate_count,
        "round_candidate_lists": round_candidate_lists,
    }


def _candidate_log_selected(entry: dict[str, Any]) -> bool:
    phase = str(entry.get("phase") or "")
    return phase in {"scheduler_repair", "beam_selected", "beam_continue"} or bool(entry.get("selected"))


def _compact_candidate(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": item.get("candidate_id"),
        "module_name": item.get("module_name") or item.get("module"),
        "repair_name": item.get("repair_name"),
        "native_target": item.get("native_target"),
        "candidate_status": item.get("candidate_status"),
        "patch_facts": item.get("patch_facts"),
        "validation_details": _compact_validation_details(item.get("validation_details")),
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    output: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                output.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return output


def make_scheduler(workspace: Path, mode: RunMode, *, disable_repair_cache: bool):
    scheduler_args = SimpleNamespace(workspace=str(workspace), disable_repair_cache=disable_repair_cache)
    scheduler = _scheduler(scheduler_args)
    policy_config = scheduler.config.get("policy") if isinstance(scheduler.config.get("policy"), dict) else {}
    scheduler.config["policy"] = {
        **policy_config,
        "enabled": bool(mode.policy_enabled),
        "strict_provider_errors": False,
    }
    scheduler.policy_manager = RepairPolicyManager(scheduler.config)
    return scheduler


def build_job(
    record: dict[str, Any],
    state: dict[str, Any],
    fmt: str,
    workspace: Path,
    mode_name: str,
    *,
    before_state: dict[str, Any] | None = None,
) -> RepairJob:
    archive_state = _archive_state_from_rollout_state(record, state, fmt)
    state_round = int(state.get("round", 0) or 0)
    route_evidence_flags = list(state.get("route_evidence_flags") or [])
    repair_history_flags = list(state.get("repair_history_flags") or [])
    residual_damage_flags = list(state.get("residual_damage_flags") or [])
    return RepairJob(
        source_input=dict(state.get("source_input") or {}),
        format=fmt,
        confidence=0.82,
        analysis_evidence=_record_analysis_evidence(record, fmt),
        analysis_prepass=_record_analysis_prepass(record, fmt),
        fuzzy_profile=_record_fuzzy_profile(record, fmt),
        extraction_failure=_runtime_extraction_failure(record, state, before_state=before_state),
        extraction_diagnostics=_runtime_extraction_diagnostics(record, state),
        damage_flags=list(state.get("damage_flags") or []),
        archive_key=f"{record.get('sample_id')}:{mode_name}:round:{state_round}",
        workspace=str(workspace),
        attempts=state_round,
        password=record.get("password"),
        archive_state=archive_state,
        repair_history=_repair_history_payload(record, state, route_evidence_flags, repair_history_flags, residual_damage_flags),
    )


def evaluate_candidate_output(
    record: dict[str, Any],
    candidate_view: dict[str, Any],
    fmt: str,
    result: RepairResult,
    state: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    source_input = candidate_view.get("source_input") if isinstance(candidate_view.get("source_input"), dict) else {}
    after_state = _state_summary(record, source_input, fmt, list(result.damage_flags or state.get("damage_flags") or []), {})
    path = Path(str(candidate_view.get("materialized_path") or source_input.get("path") or ""))
    if path.is_file():
        label_info = _verify_output_against_oracle(path, fmt, record.get("oracle") if isinstance(record.get("oracle"), dict) else {})
    else:
        label_info = {"status": str(candidate_view.get("no_output_reason") or "missing_output"), "label": 0, "completeness": 0.0}
    return label_info, after_state


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_mode: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_mode[str(row.get("mode") or "")].append(row)
    mode_summary = {mode: summarize_mode(items) for mode, items in by_mode.items()}
    pair_summary = compare_pairs(rows)
    return {"modes": mode_summary, "comparison": pair_summary}


def summarize_sample_distribution(records: list[dict[str, Any]]) -> dict[str, Any]:
    profiles = Counter(damage_profile(record) for record in records)
    layers = Counter(profile_layer(record) for record in records)
    groups = Counter(v3_profile_group(record) for record in records)
    physical_expected = Counter(str(physical_complete_expected(record)).lower() for record in records)
    warnings: list[str] = []
    if groups.get("compound", 0) == 0:
        warnings.append("compound_samples_missing")
    if groups.get("physical", 0) == 0:
        warnings.append("physical_partial_samples_missing")
    if len(profiles) < min(10, len(records)):
        warnings.append("low_profile_diversity")
    return {
        "sample_count": len(records),
        "profile_counts": dict(sorted(profiles.items())),
        "profile_layer_counts": dict(sorted(layers.items())),
        "v3_group_counts": dict(sorted(groups.items())),
        "physical_complete_expected_counts": dict(sorted(physical_expected.items())),
        "coverage_warnings": warnings,
    }


def summarize_mode(rows: list[dict[str, Any]]) -> dict[str, Any]:
    recoveries = [float(row.get("recovery_ratio", 0.0) or 0.0) for row in rows]
    walls = [float(row.get("wall_seconds", 0.0) or 0.0) for row in rows]
    terminal = Counter(str(row.get("terminal_status") or "") for row in rows)
    profiles = Counter(str(row.get("damage_profile") or "") for row in rows)
    layers = Counter(str(row.get("profile_layer") or "") for row in rows)
    groups = Counter(_v3_group_from_profile(str(row.get("damage_profile") or ""), str(row.get("profile_layer") or "")) for row in rows)
    phase_totals: dict[str, list[float]] = defaultdict(list)
    abstain_reasons: Counter[str] = Counter()
    fallback_candidate_in_request = 0
    for row in rows:
        phases = row.get("phase_timings") if isinstance(row.get("phase_timings"), dict) else {}
        for key, value in phases.items():
            try:
                phase_totals[str(key)].append(float(value or 0.0))
            except (TypeError, ValueError):
                pass
        for key, value in (row.get("policy_abstain_by_reason") if isinstance(row.get("policy_abstain_by_reason"), dict) else {}).items():
            abstain_reasons[str(key)] += int(value or 0)
        fallback_candidate_in_request += int(row.get("fallback_candidate_in_request_count", 0) or 0)
    return {
        "sample_count": len(rows),
        "complete_count": sum(1 for row in rows if bool(row.get("complete"))),
        "mean_recovery_ratio": round(sum(recoveries) / max(1, len(recoveries)), 6),
        "zero_recovery_count": sum(1 for value in recoveries if value <= 0.0),
        "timeout_count": terminal.get("timeout", 0),
        "mean_wall_seconds": round(sum(walls) / max(1, len(walls)), 4),
        "p95_wall_seconds": round(_percentile(walls, 0.95), 4),
        "policy_selected_count": sum(int(row.get("policy_selected_count", 0) or 0) for row in rows),
        "policy_fallback_count": sum(int(row.get("policy_fallback_count", 0) or 0) for row in rows),
        "policy_abstain_by_reason": dict(sorted(abstain_reasons.items())),
        "fallback_candidate_in_request_count": fallback_candidate_in_request,
        "beam_used_count": sum(int(row.get("beam_used_count", 0) or 0) for row in rows),
        "candidate_count": sum(int(row.get("candidate_count", 0) or 0) for row in rows),
        "phase_mean_seconds": {
            key: round(sum(values) / max(1, len(values)), 4)
            for key, values in sorted(phase_totals.items())
        },
        "phase_total_seconds": {
            key: round(sum(values), 4)
            for key, values in sorted(phase_totals.items())
        },
        "terminal_status_counts": dict(sorted(terminal.items())),
        "profile_counts": dict(sorted(profiles.items())),
        "profile_layer_counts": dict(sorted(layers.items())),
        "v3_group_counts": dict(sorted(groups.items())),
    }


def compare_pairs(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_sample: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        by_sample[str(row.get("sample_id") or "")][str(row.get("mode") or "")] = row
    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    complete_delta = 0
    recovery_deltas: list[float] = []
    wall_deltas: list[float] = []
    baseline_walls: list[float] = []
    for sample_id, modes in by_sample.items():
        baseline = modes.get("selector_baseline")
        model = modes.get("zip_model_policy")
        if not baseline or not model:
            continue
        recovery_delta = float(model.get("recovery_ratio", 0.0) or 0.0) - float(baseline.get("recovery_ratio", 0.0) or 0.0)
        wall_delta = float(model.get("wall_seconds", 0.0) or 0.0) - float(baseline.get("wall_seconds", 0.0) or 0.0)
        complete_delta += int(bool(model.get("complete"))) - int(bool(baseline.get("complete")))
        recovery_deltas.append(recovery_delta)
        wall_deltas.append(wall_delta)
        baseline_walls.append(float(baseline.get("wall_seconds", 0.0) or 0.0))
        payload = {
            "sample_id": sample_id,
            "damage_profile": model.get("damage_profile") or baseline.get("damage_profile"),
            "selector_recovery": baseline.get("recovery_ratio"),
            "model_recovery": model.get("recovery_ratio"),
            "recovery_delta": round(recovery_delta, 6),
            "selector_wall_seconds": baseline.get("wall_seconds"),
            "model_wall_seconds": model.get("wall_seconds"),
            "wall_delta": round(wall_delta, 4),
            "selector_path": baseline.get("repair_module_path"),
            "model_path": model.get("repair_module_path"),
            "model_policy_selected_count": model.get("policy_selected_count"),
            "model_policy_fallback_count": model.get("policy_fallback_count"),
            "model_policy_abstain_by_reason": model.get("policy_abstain_by_reason"),
            "model_fallback_selected_candidate_ids": model.get("fallback_selected_candidate_ids"),
            "model_fallback_candidate_in_request_count": model.get("fallback_candidate_in_request_count"),
        }
        if recovery_delta < -1e-6:
            regressions.append(payload)
        elif recovery_delta > 1e-6:
            improvements.append(payload)
    baseline_wall = sum(baseline_walls) / max(1, len(baseline_walls))
    model_wall_delta = sum(wall_deltas) / max(1, len(wall_deltas))
    return {
        "paired_sample_count": len(recovery_deltas),
        "model_complete_delta": complete_delta,
        "model_mean_recovery_delta": round(sum(recovery_deltas) / max(1, len(recovery_deltas)), 6),
        "model_wall_time_delta_pct": round((model_wall_delta / baseline_wall) * 100.0, 3) if baseline_wall > 0 else 0.0,
        "model_regression_count": len(regressions),
        "model_improvement_count": len(improvements),
        "model_regression_samples": sorted(regressions, key=lambda item: item["recovery_delta"])[:25],
        "model_improvement_samples": sorted(improvements, key=lambda item: item["recovery_delta"], reverse=True)[:25],
    }


def build_ab_analysis(summary: dict[str, Any], rows: list[dict[str, Any]], records: list[dict[str, Any]]) -> dict[str, Any]:
    profile_breakdown = _breakdown_delta(rows, key="damage_profile")
    layer_breakdown = _breakdown_delta(rows, key="profile_layer")
    group_breakdown = _breakdown_delta(rows, key="v3_group")
    comparison = summary.get("comparison") if isinstance(summary.get("comparison"), dict) else {}
    modes = summary.get("modes") if isinstance(summary.get("modes"), dict) else {}
    findings: list[str] = []
    if comparison.get("model_mean_recovery_delta", 0) > 0:
        findings.append(f"Model mean recovery improved by {comparison.get('model_mean_recovery_delta')}.")
    elif comparison.get("model_mean_recovery_delta", 0) < 0:
        findings.append(f"Model mean recovery regressed by {comparison.get('model_mean_recovery_delta')}.")
    if comparison.get("model_complete_delta", 0) > 0:
        findings.append(f"Model completed {comparison.get('model_complete_delta')} more samples than selector.")
    elif comparison.get("model_complete_delta", 0) < 0:
        findings.append(f"Model completed {-int(comparison.get('model_complete_delta') or 0)} fewer samples than selector.")
    distribution = summarize_sample_distribution(records)
    for warning in distribution.get("coverage_warnings") or []:
        findings.append(f"Sampling warning: {warning}.")
    model_summary = modes.get("zip_model_policy") if isinstance(modes.get("zip_model_policy"), dict) else {}
    fallback_count = int(model_summary.get("policy_fallback_count", 0) or 0)
    if fallback_count:
        findings.append(f"Model policy fell back {fallback_count} times; inspect abstain/fallback reasons.")
    return {
        "summary": summary,
        "sample_distribution": distribution,
        "profile_breakdown": profile_breakdown,
        "layer_breakdown": layer_breakdown,
        "v3_group_breakdown": group_breakdown,
        "top_regressions": comparison.get("model_regression_samples", [])[:15],
        "top_improvements": comparison.get("model_improvement_samples", [])[:15],
        "actionable_findings": findings,
    }


def _breakdown_delta(rows: list[dict[str, Any]], *, key: str) -> list[dict[str, Any]]:
    by_sample: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        by_sample[str(row.get("sample_id") or "")][str(row.get("mode") or "")] = row
    buckets: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for modes in by_sample.values():
        baseline = modes.get("selector_baseline")
        model = modes.get("zip_model_policy")
        if not baseline or not model:
            continue
        if key == "v3_group":
            bucket = _v3_group_from_profile(str(model.get("damage_profile") or baseline.get("damage_profile") or ""), str(model.get("profile_layer") or baseline.get("profile_layer") or ""))
        else:
            bucket = str(model.get(key) or baseline.get(key) or "")
        buckets[bucket].append((baseline, model))
    output: list[dict[str, Any]] = []
    for bucket, pairs in buckets.items():
        selector_recovery = [float(a.get("recovery_ratio", 0.0) or 0.0) for a, _ in pairs]
        model_recovery = [float(b.get("recovery_ratio", 0.0) or 0.0) for _, b in pairs]
        selector_complete = sum(1 for a, _ in pairs if bool(a.get("complete")))
        model_complete = sum(1 for _, b in pairs if bool(b.get("complete")))
        output.append({
            key: bucket,
            "sample_count": len(pairs),
            "selector_complete": selector_complete,
            "model_complete": model_complete,
            "complete_delta": model_complete - selector_complete,
            "selector_mean_recovery": round(sum(selector_recovery) / max(1, len(selector_recovery)), 6),
            "model_mean_recovery": round(sum(model_recovery) / max(1, len(model_recovery)), 6),
            "mean_recovery_delta": round((sum(model_recovery) - sum(selector_recovery)) / max(1, len(pairs)), 6),
            "model_zero_count": sum(1 for value in model_recovery if value <= 0),
            "selector_zero_count": sum(1 for value in selector_recovery if value <= 0),
        })
    return sorted(output, key=lambda item: (item["mean_recovery_delta"], item["complete_delta"]))


def render_ab_analysis_markdown(analysis: dict[str, Any]) -> str:
    summary = analysis.get("summary") if isinstance(analysis.get("summary"), dict) else {}
    modes = summary.get("modes") if isinstance(summary.get("modes"), dict) else {}
    comparison = summary.get("comparison") if isinstance(summary.get("comparison"), dict) else {}
    lines: list[str] = []
    lines.append("# Runtime Policy A/B Analysis")
    lines.append("")
    lines.append("## Headline")
    lines.append("")
    lines.append("| Metric | Selector + Beam | Model Single Path | Delta |")
    lines.append("|---|---:|---:|---:|")
    selector = modes.get("selector_baseline") if isinstance(modes.get("selector_baseline"), dict) else {}
    model = modes.get("zip_model_policy") if isinstance(modes.get("zip_model_policy"), dict) else {}
    lines.append(f"| Complete | {selector.get('complete_count', 0)} | {model.get('complete_count', 0)} | {comparison.get('model_complete_delta', 0)} |")
    lines.append(f"| Mean recovery | {selector.get('mean_recovery_ratio', 0)} | {model.get('mean_recovery_ratio', 0)} | {comparison.get('model_mean_recovery_delta', 0)} |")
    lines.append(f"| Zero recovery | {selector.get('zero_recovery_count', 0)} | {model.get('zero_recovery_count', 0)} | {int(model.get('zero_recovery_count', 0) or 0) - int(selector.get('zero_recovery_count', 0) or 0)} |")
    lines.append(f"| Mean wall seconds | {selector.get('mean_wall_seconds', 0)} | {model.get('mean_wall_seconds', 0)} | {comparison.get('model_wall_time_delta_pct', 0)}% |")
    lines.append(f"| Timeout | {selector.get('timeout_count', 0)} | {model.get('timeout_count', 0)} | {int(model.get('timeout_count', 0) or 0) - int(selector.get('timeout_count', 0) or 0)} |")
    lines.append("")
    lines.append("## Sampling Coverage")
    lines.append("")
    dist = analysis.get("sample_distribution") if isinstance(analysis.get("sample_distribution"), dict) else {}
    lines.append("| Group | Count |")
    lines.append("|---|---:|")
    for key, value in (dist.get("v3_group_counts") or {}).items():
        lines.append(f"| {key} | {value} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    findings = analysis.get("actionable_findings") if isinstance(analysis.get("actionable_findings"), list) else []
    if findings:
        for item in findings:
            lines.append(f"- {item}")
    else:
        lines.append("- No obvious sampling or policy issues were detected.")
    lines.append("")
    lines.append("## Layer Breakdown")
    lines.append("")
    lines.extend(_markdown_table(analysis.get("layer_breakdown") or [], ["profile_layer", "sample_count", "selector_complete", "model_complete", "complete_delta", "selector_mean_recovery", "model_mean_recovery", "mean_recovery_delta"]))
    lines.append("")
    lines.append("## Profile Breakdown")
    lines.append("")
    lines.extend(_markdown_table((analysis.get("profile_breakdown") or [])[:30], ["damage_profile", "sample_count", "selector_complete", "model_complete", "complete_delta", "selector_mean_recovery", "model_mean_recovery", "mean_recovery_delta"]))
    lines.append("")
    lines.append("## Top Regressions")
    lines.append("")
    lines.extend(_markdown_table(analysis.get("top_regressions") or [], ["sample_id", "damage_profile", "selector_recovery", "model_recovery", "recovery_delta", "selector_path", "model_path"]))
    lines.append("")
    lines.append("## Top Improvements")
    lines.append("")
    lines.extend(_markdown_table(analysis.get("top_improvements") or [], ["sample_id", "damage_profile", "selector_recovery", "model_recovery", "recovery_delta", "selector_path", "model_path"]))
    lines.append("")
    return "\n".join(lines)


def _markdown_table(rows: list[dict[str, Any]], columns: list[str]) -> list[str]:
    if not rows:
        return ["_No rows._"]
    output = ["| " + " | ".join(columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    for row in rows:
        cells = [_markdown_cell(row.get(column)) for column in columns]
        output.append("| " + " | ".join(cells) + " |")
    return output


def _markdown_cell(value: Any) -> str:
    if isinstance(value, list):
        text = " -> ".join(str(item) for item in value[:8])
    elif isinstance(value, dict):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value if value is not None else "")
    return text.replace("|", "\\|").replace("\n", " ")[:240]


def prepare_record(record: dict[str, Any]) -> dict[str, Any]:
    prepared = dict(record)
    source_input = dict(prepared.get("damaged_input") or {"kind": "file", "path": prepared.get("damaged_path"), "format_hint": "zip"})
    _attach_split_volumes(source_input, prepared)
    prepared["damaged_input"] = source_input
    tags = prepared.get("zip_container_tags") or []
    if isinstance(tags, list):
        tag_flags = {str(item) for item in tags if str(item) in {"sfx", "carrier_prefix", "carrier_archive", "embedded_archive"}}
        if tag_flags:
            prepared["damage_flags"] = _dedupe_str([*list(prepared.get("damage_flags") or []), *list(tag_flags)])
    route_evidence = zip_route_evidence_flags(prepared)
    if route_evidence:
        prepared["route_evidence_flags"] = _dedupe_str([*list(prepared.get("route_evidence_flags") or []), *route_evidence])
        prepared["damage_flags"] = _dedupe_str([*list(prepared.get("damage_flags") or []), *route_evidence])
        prepared["runtime_damage_flags"] = _dedupe_str([*list(prepared.get("runtime_damage_flags") or prepared.get("damage_flags") or []), *route_evidence])
    if source_input.get("parts"):
        prepared["split_sidecars_available"] = True
    return prepared


def _load_record(row: dict[str, Any]) -> dict[str, Any]:
    row = _augment_runtime_graph_row(row)
    damage_json_path = Path(str(row.get("damage_json_path") or ""))
    if damage_json_path and not damage_json_path.is_absolute():
        damage_json_path = ROOT / damage_json_path
    if damage_json_path.is_file():
        try:
            record = json.loads(damage_json_path.read_text(encoding="utf-8"))
        except Exception:
            record = dict(row)
    else:
        record = dict(row)
    for key in ("sample_id", "damage_json_path", "damaged_path", "damaged_file_name", "material_format", "material_sample_id", "source_derivation", "zip_variant", "zip_container_tags", "zip_structure_features"):
        if row.get(key) is not None and record.get(key) is None:
            record[key] = row.get(key)
    return _resolve_record_paths(record)


def _augment_runtime_graph_row(row: dict[str, Any]) -> dict[str, Any]:
    """Recover material paths from runtime-graph rows.

    New runtime graph action rows intentionally store the production policy
    payload instead of duplicating manifest fields.  For A/B evaluation we need
    to map the row back to the material damage.json so oracle verification and
    split sidecar facts are identical to training collection.
    """
    if row.get("damaged_path") or row.get("damage_json_path") or isinstance(row.get("damaged_input"), dict):
        return row
    source_path = _runtime_graph_source_path(row)
    if not source_path:
        damage_json = _damage_json_for_sample_id(str(row.get("sample_id") or ""))
        if not damage_json:
            return row
        output = dict(row)
        output["damage_json_path"] = str(damage_json)
        try:
            record = json.loads(damage_json.read_text(encoding="utf-8"))
        except Exception:
            record = {}
        damaged = str((record.get("damaged_input") or {}).get("path") or record.get("damaged_path") or "")
        if damaged:
            output["damaged_path"] = damaged
            output["damaged_input"] = {"kind": "file", "path": damaged, "format_hint": row.get("material_format") or "zip"}
        return output
    output = dict(row)
    output["damaged_path"] = source_path
    output["damaged_input"] = {"kind": "file", "path": source_path, "format_hint": row.get("material_format") or "zip"}
    damage_json = _sibling_damage_json(Path(source_path), sample_id=str(row.get("sample_id") or ""))
    if damage_json:
        output["damage_json_path"] = str(damage_json)
    return output


def _runtime_graph_source_path(row: dict[str, Any]) -> str:
    stable = row.get("stable_features") if isinstance(row.get("stable_features"), dict) else {}
    context = stable.get("runtime_context") if isinstance(stable.get("runtime_context"), dict) else {}
    projection = context.get("knowledge_projection") if isinstance(context.get("knowledge_projection"), dict) else {}
    fingerprint = projection.get("source_fingerprint") if isinstance(projection.get("source_fingerprint"), dict) else {}
    candidates: list[Any] = []
    if fingerprint.get("path"):
        candidates.append(fingerprint.get("path"))
    source = fingerprint.get("source") if isinstance(fingerprint.get("source"), dict) else {}
    if source.get("path"):
        candidates.append(source.get("path"))
    for part in source.get("parts") or []:
        if isinstance(part, dict) and part.get("path"):
            candidates.append(part.get("path"))
    for candidate in candidates:
        path = str(candidate or "")
        if path and Path(path).is_file():
            return path
    return ""


def _sibling_damage_json(source_path: Path, *, sample_id: str) -> Path | None:
    parent = source_path.parent
    if not parent.is_dir():
        return None
    matches = sorted(parent.glob("*.damage.json"))
    if not matches:
        return None
    if sample_id:
        for item in matches:
            try:
                payload = json.loads(item.read_text(encoding="utf-8"))
            except Exception:
                continue
            if str(payload.get("sample_id") or "") == sample_id:
                return item
    return matches[0]


_DAMAGE_JSON_BY_SAMPLE_ID: dict[str, Path] | None = None


def _damage_json_for_sample_id(sample_id: str) -> Path | None:
    if not sample_id:
        return None
    global _DAMAGE_JSON_BY_SAMPLE_ID
    if _DAMAGE_JSON_BY_SAMPLE_ID is None:
        index: dict[str, Path] = {}
        material_zip = ROOT / "repair_training" / "material" / "zip"
        if material_zip.is_dir():
            for path in material_zip.rglob("*.damage.json"):
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                key = str(payload.get("sample_id") or "")
                if key and key not in index:
                    index[key] = path
        _DAMAGE_JSON_BY_SAMPLE_ID = index
    return _DAMAGE_JSON_BY_SAMPLE_ID.get(sample_id)


def _resolve_record_paths(record: dict[str, Any]) -> dict[str, Any]:
    output = dict(record)
    for key in ("damaged_path", "source_path", "damage_json_path"):
        if output.get(key):
            output[key] = str(_resolve_path(output[key]))
    for key in ("damaged_input", "clean_input"):
        value = output.get(key)
        if isinstance(value, dict):
            value = dict(value)
            if value.get("path"):
                value["path"] = str(_resolve_path(value["path"]))
            output[key] = value
    if not isinstance(output.get("damaged_input"), dict):
        output["damaged_input"] = {"kind": "file", "path": output.get("damaged_path"), "format_hint": output.get("material_format") or "zip"}
    elif not output["damaged_input"].get("path") and output.get("damaged_path"):
        output["damaged_input"] = {**output["damaged_input"], "path": output.get("damaged_path"), "kind": output["damaged_input"].get("kind") or "file", "format_hint": output["damaged_input"].get("format_hint") or "zip"}
    return output


def _iter_unique_rows(path: Path) -> Iterable[dict[str, Any]]:
    seen: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            sample_id = str(row.get("sample_id") or "")
            if not sample_id or sample_id in seen:
                continue
            if not _row_has_material_source(row):
                continue
            seen.add(sample_id)
            yield row


def _row_has_material_source(row: dict[str, Any]) -> bool:
    if row.get("damaged_path") or row.get("damage_json_path"):
        return True
    damaged_input = row.get("damaged_input")
    if isinstance(damaged_input, dict) and damaged_input.get("path"):
        return True
    return bool(_runtime_graph_source_path(row) or _damage_json_for_sample_id(str(row.get("sample_id") or "")))


def damage_profile(record: dict[str, Any]) -> str:
    profile = str(record.get("damage_profile") or "")
    if profile:
        return profile
    sample_id = str(record.get("sample_id") or "")
    for marker in (*V3_BASIC_PROFILES, *V3_COMPOUND_PROFILES, *V3_PHYSICAL_PROFILES, *PRIORITY_PROFILES):
        if marker in sample_id:
            return marker
    return sample_id.rsplit("_", 1)[0] if sample_id else ""


def profile_layer(record: dict[str, Any]) -> str:
    layer = str(record.get("profile_layer") or record.get("damage_layer") or record.get("actual_damage_layer") or "").strip()
    if layer:
        return layer
    profile = damage_profile(record)
    if profile.startswith("compound_"):
        return "compound"
    if profile.startswith("partial_"):
        return "physical"
    return "basic"


def physical_complete_expected(record: dict[str, Any]) -> bool:
    value = record.get("physical_complete_expected")
    if value is None:
        return not damage_profile(record).startswith("partial_")
    return bool(value)


def v3_profile_group(record: dict[str, Any]) -> str:
    return _v3_group_from_profile(damage_profile(record), profile_layer(record))


def _v3_group_from_profile(profile: str, layer: str = "") -> str:
    if profile in V3_PHYSICAL_PROFILES or profile.startswith("partial_") or str(layer).lower() in {"physical", "partial", "partial_recoverable"}:
        return "physical"
    if profile in V3_COMPOUND_PROFILES or profile.startswith("compound_") or str(layer).lower() == "compound":
        return "compound"
    return "basic"


def _candidate_selection(result: RepairResult) -> dict[str, Any]:
    diagnosis = result.diagnosis if isinstance(result.diagnosis, dict) else {}
    selection = diagnosis.get("candidate_selection") if isinstance(diagnosis.get("candidate_selection"), dict) else {}
    return dict(selection)


def _public_candidate_list(selection: dict[str, Any]) -> list[dict[str, Any]]:
    raw = selection.get("candidates") if isinstance(selection.get("candidates"), list) else []
    output: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        output.append({
            "candidate_id": item.get("candidate_id"),
            "module_name": item.get("module_name") or item.get("module"),
            "repair_name": item.get("repair_name"),
            "native_target": item.get("native_target"),
            "candidate_status": item.get("candidate_status"),
            "patch_facts": item.get("patch_facts"),
            "validation_details": _compact_validation_details(item.get("validation_details")),
        })
    return output


def _compact_validation_details(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    keys = (
        "policy",
        "crc_match_count",
        "kept_payload_verified_count",
        "duplicate_group_count",
        "ambiguous_duplicate_group_count",
        "dropped_entry_count",
    )
    return {key: value.get(key) for key in keys if key in value}


def _result_terminal_status(result: RepairResult) -> str:
    if result.status:
        return str(result.status)
    if result.message:
        return "unrepairable"
    return "no_candidates"


def _resolve_path(value: Any) -> Path:
    if value is None or str(value) == "":
        return Path("")
    path = Path(str(value))
    return path if path.is_absolute() else ROOT / path


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)[:180]


def _matches(value: str, wanted: str) -> bool:
    return wanted == value or wanted in value


def _matches_any(value: str, filters: list[str]) -> bool:
    return any(_matches(value, item) for item in filters)


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(math.ceil(q * len(ordered)) - 1)))
    return ordered[index]


if __name__ == "__main__":
    raise SystemExit(main())
