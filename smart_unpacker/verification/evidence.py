from dataclasses import dataclass
from typing import Any

from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.passwords import PasswordSession


@dataclass(frozen=True)
class VerificationEvidence:
    task: ArchiveTask
    extraction_result: ExtractionResult
    archive_path: str
    archive_parts: list[str]
    output_dir: str
    password: str | None
    fact_bag: Any
    health: dict[str, Any]
    analysis: dict[str, Any]
    selected_codepage: str | None = None


def build_verification_evidence(
    task: ArchiveTask,
    extraction_result: ExtractionResult,
    password_session: PasswordSession | None = None,
) -> VerificationEvidence:
    fact_bag = task.fact_bag
    password = extraction_result.password_used
    if password is None and password_session is not None:
        password = password_session.get_resolved(task.key)
    return VerificationEvidence(
        task=task,
        extraction_result=extraction_result,
        archive_path=extraction_result.archive or task.main_path,
        archive_parts=list(extraction_result.all_parts or task.all_parts or []),
        output_dir=extraction_result.out_dir,
        password=password,
        fact_bag=fact_bag,
        health=dict(fact_bag.get("resource.health") or {}),
        analysis=dict(fact_bag.get("resource.analysis") or {}),
        selected_codepage=extraction_result.selected_codepage,
    )

