"""Central policy and guarded execution for managed extraction-output cleanup."""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import asdict, dataclass
from enum import Enum


LOGGER = logging.getLogger(__name__)
INTERNAL_METADATA_DIR = ".sunpack"


class OutputCleanupEvent(str, Enum):
    """A finite set of reasons for removing extraction-owned output."""

    EXTRACTION_ABORT = "extraction_abort"
    EXTRACT_RETRY = "extract_retry"
    VERIFICATION_RETRY = "verification_retry"
    UNRECOVERABLE_FAILURE = "unrecoverable_failure"
    RETRY_EXHAUSTED = "retry_exhausted"
    EMPTY_REPAIR_OUTPUT = "empty_repair_output"
    TERMINAL_FAILURE = "terminal_failure"
    POLICY_REJECTED_PARTIAL = "policy_rejected_partial"
    BEAM_CANDIDATE_PREPARE = "beam_candidate_prepare"
    BEAM_CANDIDATE_REJECTED = "beam_candidate_rejected"
    BEAM_CONTINUE = "beam_continue"
    INCUMBENT_REPLACE = "incumbent_replace"
    INCUMBENT_DISCARD = "incumbent_discard"
    PROMOTE_REPLACE_TARGET = "promote_replace_target"
    PARTIAL_FILE_DISCARD = "partial_file_discard"
    REPAIR_POLICY_STOP = "repair_policy_stop"


class OutputRole(str, Enum):
    CANONICAL = "canonical"
    BEAM_CANDIDATE = "beam_candidate"
    INCUMBENT = "incumbent"
    PARTIAL_FILE = "partial_file"
    REPAIR_WORKSPACE = "repair_workspace"


@dataclass(frozen=True)
class OutputOwnership:
    """The path boundary that authorizes one cleanup operation."""

    planned_output_dir: str = ""
    workspace_root: str = ""


@dataclass(frozen=True)
class OutputCleanupRequest:
    event: OutputCleanupEvent
    role: OutputRole
    path: str
    ownership: OutputOwnership
    allow_nonempty: bool | None = None


@dataclass(frozen=True)
class OutputCleanupResult:
    requested: bool = True
    eligible: bool = False
    cleaned: bool = False
    already_absent: bool = False
    reason: str = ""
    event: str = ""
    role: str = ""
    path: str = ""
    payload_file_count: int = 0
    payload_bytes: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class OutputCleanupExecutor:
    """The only component allowed to physically remove managed output paths."""

    @staticmethod
    def remove_tree(path: str) -> None:
        shutil.rmtree(path)

    @staticmethod
    def remove_file(path: str) -> None:
        os.unlink(path)


class OutputCleanupManager:
    """Authorize, apply, and report all extraction-output cleanup operations."""

    def __init__(self, executor: OutputCleanupExecutor | None = None):
        self.executor = executor or OutputCleanupExecutor()

    def cleanup_canonical(
        self,
        path: str,
        *,
        event: OutputCleanupEvent,
        planned_output_dir: str | None = None,
        allow_nonempty: bool | None = None,
    ) -> OutputCleanupResult:
        return self.handle(OutputCleanupRequest(
            event=event,
            role=OutputRole.CANONICAL,
            path=path,
            ownership=OutputOwnership(planned_output_dir=planned_output_dir or path),
            allow_nonempty=allow_nonempty,
        ))

    def cleanup_scoped_path(
        self,
        path: str,
        *,
        event: OutputCleanupEvent,
        role: OutputRole,
        workspace_root: str,
    ) -> OutputCleanupResult:
        return self.handle(OutputCleanupRequest(
            event=event,
            role=role,
            path=path,
            ownership=OutputOwnership(workspace_root=workspace_root),
        ))

    def cleanup_partial_file(self, path: str, *, output_root: str) -> OutputCleanupResult:
        return self.handle(OutputCleanupRequest(
            event=OutputCleanupEvent.PARTIAL_FILE_DISCARD,
            role=OutputRole.PARTIAL_FILE,
            path=path,
            ownership=OutputOwnership(planned_output_dir=output_root),
        ))

    def handle(self, request: OutputCleanupRequest) -> OutputCleanupResult:
        event = request.event.value
        role = request.role.value
        path = _absolute(request.path)
        base = {
            "event": event,
            "role": role,
            "path": path,
        }
        if not path:
            return OutputCleanupResult(reason="empty_path", **base)
        if _is_filesystem_root(path):
            return OutputCleanupResult(reason="filesystem_root_refused", **base)
        if not self._owned(request.role, path, request.ownership):
            return OutputCleanupResult(reason="unowned_output", **base)
        if not os.path.lexists(path):
            return OutputCleanupResult(
                eligible=True,
                already_absent=True,
                reason="already_absent",
                **base,
            )
        if os.path.islink(path):
            return OutputCleanupResult(reason="symlink_refused", **base)

        is_directory = os.path.isdir(path)
        if request.role != OutputRole.PARTIAL_FILE and not is_directory and request.role != OutputRole.REPAIR_WORKSPACE:
            return OutputCleanupResult(reason="managed_directory_required", **base)
        if request.role == OutputRole.PARTIAL_FILE and not os.path.isfile(path):
            return OutputCleanupResult(reason="managed_file_required", **base)

        payload_file_count = 0
        payload_bytes = 0
        allow_nonempty = request.allow_nonempty
        if allow_nonempty is None:
            allow_nonempty = request.event != OutputCleanupEvent.TERMINAL_FAILURE
        if is_directory and not allow_nonempty:
            inventory = _payload_inventory(path)
            if inventory is None:
                return OutputCleanupResult(reason="output_inventory_failed", **base)
            payload_file_count, payload_bytes = inventory
            if payload_bytes > 0:
                return OutputCleanupResult(
                    reason="nonempty_payload",
                    payload_file_count=payload_file_count,
                    payload_bytes=payload_bytes,
                    **base,
                )

        try:
            if is_directory:
                self.executor.remove_tree(path)
            else:
                self.executor.remove_file(path)
        except OSError as exc:
            LOGGER.warning("output cleanup failed event=%s role=%s path=%s: %s", event, role, path, exc)
            return OutputCleanupResult(
                eligible=True,
                reason="cleanup_failed",
                error=str(exc),
                payload_file_count=payload_file_count,
                payload_bytes=payload_bytes,
                **base,
            )
        LOGGER.info("output cleaned event=%s role=%s path=%s", event, role, path)
        return OutputCleanupResult(
            eligible=True,
            cleaned=True,
            reason=(
                "policy_rejected_partial_cleaned"
                if request.event == OutputCleanupEvent.POLICY_REJECTED_PARTIAL
                else "cleaned"
            ),
            payload_file_count=payload_file_count,
            payload_bytes=payload_bytes,
            **base,
        )

    @staticmethod
    def _owned(role: OutputRole, path: str, ownership: OutputOwnership) -> bool:
        if role == OutputRole.CANONICAL:
            planned = _absolute(ownership.planned_output_dir)
            return bool(planned and _same_path(path, planned))
        if role == OutputRole.PARTIAL_FILE:
            root = _absolute(ownership.planned_output_dir)
            return bool(root and _is_strict_descendant(path, root))
        root = _absolute(ownership.workspace_root)
        return bool(root and _is_strict_descendant(path, root))


DEFAULT_OUTPUT_CLEANUP_MANAGER = OutputCleanupManager()


def _absolute(path: str) -> str:
    return os.path.abspath(str(path or "")) if path else ""


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(_absolute(left)) == os.path.normcase(_absolute(right))


def _is_strict_descendant(path: str, root: str) -> bool:
    path = _absolute(path)
    root = _absolute(root)
    if not path or not root or _same_path(path, root):
        return False
    try:
        return os.path.normcase(os.path.commonpath((path, root))) == os.path.normcase(root)
    except ValueError:
        return False


def _is_filesystem_root(path: str) -> bool:
    parent = os.path.dirname(_absolute(path))
    return _same_path(parent, path)


def _payload_inventory(root: str) -> tuple[int, int] | None:
    file_count = 0
    byte_count = 0
    try:
        for current, directories, files in os.walk(root, followlinks=False, onerror=_raise_walk_error):
            if _same_path(current, root):
                directories[:] = [name for name in directories if name != INTERNAL_METADATA_DIR]
            for name in [*directories, *files]:
                path = os.path.join(current, name)
                if not os.path.islink(path):
                    continue
                file_count += 1
                byte_count += max(1, int(os.lstat(path).st_size))
            for name in files:
                path = os.path.join(current, name)
                if os.path.islink(path):
                    continue
                file_count += 1
                byte_count += int(os.stat(path, follow_symlinks=False).st_size)
    except OSError:
        return None
    return file_count, byte_count


def _raise_walk_error(error: OSError) -> None:
    raise error
