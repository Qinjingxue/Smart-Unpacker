from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sunpack.contracts.tasks import ArchiveTask
from sunpack.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_payload


def write_filesystem_task(task: ArchiveTask) -> None:
    knowledge = ensure_knowledge(task)
    main_path = str(task.main_path or "")
    stat = _stat_payload(main_path)
    payload: dict[str, Any] = {
        "path": main_path,
        "absolute_path": os.path.abspath(main_path) if main_path else "",
        "detected_ext": str(task.detected_ext or task.fact_bag.get("file.detected_ext") or ""),
        "split_members": list(task.all_parts or []),
        **stat,
    }
    write_payload(knowledge, "filesystem", payload, source_layer="filesystem", source_module="task")
    write_payload(
        knowledge,
        "source.input",
        {
            "kind": "file",
            "path": main_path,
            "format_hint": str(task.fact_bag.get("archive.format_hint") or task.detected_ext or task.fact_bag.get("file.detected_ext") or ""),
            "parts": list(task.all_parts or []),
        },
        source_layer="filesystem",
        source_module="task",
    )
    commit_task_knowledge(task, knowledge)


def _stat_payload(path: str) -> dict[str, Any]:
    if not path:
        return {}
    try:
        stat = Path(path).stat()
    except OSError:
        return {"exists": False}
    return {
        "exists": True,
        "size": int(stat.st_size),
        "mtime_ns": int(stat.st_mtime_ns),
        "suffix": Path(path).suffix.lower(),
    }
