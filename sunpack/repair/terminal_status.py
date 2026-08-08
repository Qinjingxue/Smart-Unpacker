from __future__ import annotations

from typing import Any

from sunpack.repair.config import repair_system_mode
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.contracts.verification import DECISION_REPAIR


REPAIR_STATUS_DISABLED_BY_EDITION = "disabled_by_edition"
REPAIR_STATUS_STOPPED = "stopped"
REPAIR_STATUS_ATTEMPTED_NO_RECOVERY = "attempted_no_recovery"
REPAIR_STATUS_NO_APPLICABLE_REPAIR = "no_applicable_repair"


def terminal_repair_status(
    task: Any,
    *,
    decision_hint: str = "",
    repair_enabled: bool,
    attempt_source: str = "",
    repair_module: str = "",
    selected_attempt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Describe why a repair-requested task reached a failed terminal state."""

    loop = knowledge_view.repair_loop(task)
    attempts = knowledge_view.repair_attempts(task)
    candidate_log = knowledge_view.repair_candidate_log(task)
    entered = bool(getattr(task, "fact_bag", None) and task.fact_bag.get("pipeline.repair_entered"))
    requested = str(decision_hint or "") == DECISION_REPAIR or entered or attempts > 0 or bool(loop)
    if not requested:
        return {}

    system = repair_system_mode()
    terminal = loop.get("terminal") if isinstance(loop.get("terminal"), dict) else {}
    terminal_reason = str(loop.get("terminal_reason") or terminal.get("reason") or "")
    if system == "lite" or not repair_enabled:
        status = REPAIR_STATUS_DISABLED_BY_EDITION if system == "lite" else REPAIR_STATUS_NO_APPLICABLE_REPAIR
    elif terminal_reason:
        status = REPAIR_STATUS_STOPPED
    elif entered or attempts > 0 or candidate_log:
        status = REPAIR_STATUS_ATTEMPTED_NO_RECOVERY
    else:
        status = REPAIR_STATUS_NO_APPLICABLE_REPAIR

    payload: dict[str, Any] = {
        "system": system,
        "status": status,
        "requested": True,
        "entered": entered,
        "attempts": attempts,
    }
    if terminal_reason:
        payload["terminal_reason"] = terminal_reason
    if terminal:
        payload["terminal"] = dict(terminal)
    if attempt_source:
        payload["selected_attempt_source"] = str(attempt_source)
    if repair_module:
        payload["selected_module"] = str(repair_module)
    if selected_attempt:
        payload["selected_attempt"] = dict(selected_attempt)
    if candidate_log:
        payload["candidate_count"] = len(candidate_log)
    return payload
