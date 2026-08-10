from __future__ import annotations

import logging
import os
import shutil
from dataclasses import asdict, dataclass


LOGGER = logging.getLogger(__name__)
REPAIR_ENTERED_FACT = "pipeline.repair_entered"
INTERNAL_METADATA_DIR = ".sunpack"


@dataclass(frozen=True)
class FailedOutputCleanupResult:
    cleaned: bool = False
    eligible: bool = False
    reason: str = ""
    output_dir: str = ""
    payload_file_count: int = 0
    payload_bytes: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def cleanup_failed_output_if_eligible(
    output_dir: str,
    *,
    planned_output_dir: str,
    failed: bool,
    repair_entered: bool,
    force_owned_output_cleanup: bool = False,
) -> FailedOutputCleanupResult:
    """Apply the postprocess cleanup policy to a terminal extraction output."""
    path = os.path.abspath(str(output_dir or "")) if output_dir else ""
    planned = os.path.abspath(str(planned_output_dir or "")) if planned_output_dir else ""
    if not failed:
        return FailedOutputCleanupResult(reason="task_not_failed", output_dir=path)
    if repair_entered and not force_owned_output_cleanup:
        return FailedOutputCleanupResult(reason="repair_entered", output_dir=path)
    if not path or not planned or os.path.normcase(path) != os.path.normcase(planned):
        return FailedOutputCleanupResult(reason="unowned_output_dir", output_dir=path)
    if not os.path.isdir(path) or os.path.islink(path) or _is_filesystem_root(path):
        return FailedOutputCleanupResult(reason="output_dir_missing_or_unsafe", output_dir=path)

    inventory = _zero_payload_inventory(path)
    if inventory is None:
        return FailedOutputCleanupResult(reason="output_inventory_failed", output_dir=path)
    file_count, byte_count = inventory
    if byte_count > 0 and not force_owned_output_cleanup:
        return FailedOutputCleanupResult(
            reason="nonempty_payload",
            output_dir=path,
            payload_file_count=file_count,
            payload_bytes=byte_count,
        )
    try:
        shutil.rmtree(path)
    except OSError as exc:
        LOGGER.warning("failed to clean empty failed output %s: %s", path, exc)
        return FailedOutputCleanupResult(
            eligible=True,
            reason=f"cleanup_failed: {exc}",
            output_dir=path,
            payload_file_count=file_count,
            payload_bytes=byte_count,
        )
    LOGGER.info("cleaned failed output: %s", path)
    return FailedOutputCleanupResult(
        cleaned=True,
        eligible=True,
        reason="policy_rejected_partial_cleaned" if force_owned_output_cleanup else "cleaned",
        output_dir=path,
        payload_file_count=file_count,
        payload_bytes=byte_count,
    )


def _zero_payload_inventory(root: str) -> tuple[int, int] | None:
    file_count = 0
    byte_count = 0
    try:
        for current, directories, files in os.walk(root, followlinks=False, onerror=_raise_walk_error):
            if os.path.normcase(os.path.abspath(current)) == os.path.normcase(os.path.abspath(root)):
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


def _is_filesystem_root(path: str) -> bool:
    parent = os.path.dirname(os.path.abspath(path))
    return os.path.normcase(parent) == os.path.normcase(os.path.abspath(path))
