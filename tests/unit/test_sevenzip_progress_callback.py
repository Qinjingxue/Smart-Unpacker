import json
import queue
from types import SimpleNamespace

from sunpack.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner


def test_persistent_worker_progress_event_is_forwarded_to_task_callback():
    worker = SimpleNamespace(
        process=None,
        stdout_queue=queue.Queue(),
        stderr_queue=queue.Queue(),
    )
    worker.stdout_queue.put(json.dumps({
        "type": "progress",
        "completed_bytes": 25,
        "total_bytes": 100,
    }) + "\n")
    worker.stdout_queue.put(json.dumps({"type": "result", "status": "ok"}) + "\n")
    task = SimpleNamespace(main_path="archive.7z", fact_bag=None)
    events = []
    runner = SevenZipRunner({"process_sample_interval_ms": 100})
    runner.progress_callback = lambda current_task, event: events.append((current_task, event))

    _stdout, _stderr, returncode, reusable = runner._read_persistent_worker_result(worker, None, task)

    assert returncode == 0
    assert reusable is True
    assert events == [(task, {"type": "progress", "completed_bytes": 25, "total_bytes": 100})]
