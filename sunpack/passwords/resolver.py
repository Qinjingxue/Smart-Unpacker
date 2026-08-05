from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.contracts.detection import FactBag
from sunpack.passwords.candidates import PasswordCandidatePipeline
from sunpack.passwords.fingerprint import build_archive_fingerprint
from sunpack.passwords.job import PasswordJob
from sunpack.passwords.result import PasswordResolution, PasswordResolutionStatus
from sunpack.passwords.scheduler import PasswordScheduler, PasswordSearchResult, PasswordSearchStatus
from sunpack.passwords.session import PasswordSession


@dataclass
class _PendingPasswordPlan:
    candidates: list[str]
    fingerprint_key: str
    candidate_evidence: str = ""


class PasswordResolver:
    """Plan bounded password checks and defer ambiguous proof to extraction.

    Candidate origin never changes verification semantics.  Every password goes
    through the same fast-verifier plan; candidates lacking a bounded proof are
    queued for confirmation by the real extraction transaction.
    """

    def __init__(
        self,
        password_tester,
        password_session: PasswordSession | None = None,
        password_scheduler: PasswordScheduler | None = None,
    ):
        self.password_tester = password_tester
        self.password_session = password_session or PasswordSession()
        self.password_scheduler = password_scheduler or password_tester.password_scheduler
        self._pending_confirmation: dict[str, _PendingPasswordPlan] = {}
        self._lock = RLock()

    def resolve(
        self,
        archive_path: str,
        fact_bag: FactBag | None = None,
        part_paths: list[str] | None = None,
        archive_key: str = "",
        directory_passwords: list[str] | None = None,
    ) -> PasswordResolution:
        archive_key = archive_key or self._archive_key_from_fact_bag(fact_bag) or archive_path
        if self.password_session.has_resolved(archive_key):
            return PasswordResolution(
                password=self.password_session.get_resolved(archive_key),
                status=PasswordResolutionStatus.RESOLVED,
                archive_key=archive_key,
            )

        if self._facts_confirm_unencrypted(fact_bag):
            return self._remember(
                archive_key,
                "",
                status=PasswordResolutionStatus.UNENCRYPTED,
                encrypted=False,
            )

        if self._facts_have_patches(fact_bag) and self._facts_require_password(fact_bag):
            return PasswordResolution(
                password=None,
                status=PasswordResolutionStatus.PASSWORD_REQUIRED,
                error_text="password verification is unsupported for patched archive state without a resolved password",
                archive_key=archive_key,
                encrypted=True,
            )

        pending = self._take_pending(archive_key)
        if pending is not None:
            password, fingerprint_key, candidate_evidence = pending
            return self._confirmation_resolution(
                archive_key,
                password,
                fingerprint_key,
                fact_bag,
                candidate_evidence=candidate_evidence,
            )

        fingerprint = build_archive_fingerprint(archive_path, part_paths)

        directory_passwords = list(directory_passwords or [])
        candidates = self.password_tester.password_store.candidates(directory_passwords=directory_passwords)
        if not candidates:
            if self._facts_require_password(fact_bag):
                return PasswordResolution(
                    password=None,
                    status=PasswordResolutionStatus.PASSWORD_REQUIRED,
                    error_text="archive requires a password but no candidates were provided",
                    archive_key=archive_key,
                    encrypted=True,
                )
            # Unknown encryption state: let the real extraction prove the empty
            # password instead of performing a complete preflight test pass.
            return self._confirmation_resolution(archive_key, "", fingerprint.key, fact_bag)

        search = self._plan_password_search(
            archive_path,
            fact_bag=fact_bag,
            part_paths=part_paths,
            fingerprint=fingerprint,
            directory_passwords=directory_passwords,
        )
        if search.status == PasswordSearchStatus.FOUND:
            resolution = self._remember_search(archive_key, search, encrypted=True)
            if resolution.password is not None:
                self._promote_success(resolution.password)
            return resolution
        if search.extraction_candidates:
            first, *remaining = search.extraction_candidates
            with self._lock:
                self._pending_confirmation[archive_key] = _PendingPasswordPlan(
                    list(remaining),
                    fingerprint.key,
                    search.extraction_candidate_evidence,
                )
            return self._confirmation_resolution(
                archive_key,
                first,
                fingerprint.key,
                fact_bag,
                candidate_evidence=search.extraction_candidate_evidence,
            )
        return self._remember_search(
            archive_key,
            search,
            encrypted=True if self._facts_require_password(fact_bag) else None,
        )

    def confirm_extraction(self, resolution: PasswordResolution) -> None:
        if not resolution.requires_extraction_confirmation or resolution.password is None:
            return
        self.password_session.set_resolved(resolution.archive_key, resolution.password)
        self.password_scheduler.remember_extraction_success(resolution.fingerprint_key, resolution.password)
        self._promote_success(resolution.password)
        with self._lock:
            self._pending_confirmation.pop(resolution.archive_key, None)

    def reject_extraction_candidate(self, resolution: PasswordResolution) -> None:
        if not resolution.requires_extraction_confirmation or resolution.password is None:
            return
        self.password_scheduler.remember_extraction_rejection(resolution.fingerprint_key, resolution.password)

    def has_pending_candidates(self, archive_key: str) -> bool:
        with self._lock:
            plan = self._pending_confirmation.get(archive_key)
            return bool(plan and plan.candidates)

    def _plan_password_search(
        self,
        archive_path: str,
        *,
        fact_bag: FactBag | None,
        part_paths: list[str] | None,
        fingerprint,
        directory_passwords: list[str] | None,
    ) -> PasswordSearchResult:
        archive_input = self._archive_input_for_password_probe(fact_bag)
        candidates = PasswordCandidatePipeline.from_password_store(
            self.password_tester.password_store,
            directory_passwords=directory_passwords,
        )
        return self.password_scheduler.plan_for_extraction(PasswordJob(
            archive_path=archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
            fingerprint=fingerprint,
            candidates=candidates,
        ))

    def _take_pending(self, archive_key: str) -> tuple[str, str, str] | None:
        with self._lock:
            plan = self._pending_confirmation.get(archive_key)
            if not plan or not plan.candidates:
                return None
            return plan.candidates.pop(0), plan.fingerprint_key, plan.candidate_evidence

    def _promote_success(self, password: str) -> None:
        self.password_tester.add_recent_password(password)
        with self._lock:
            for plan in self._pending_confirmation.values():
                if password not in plan.candidates:
                    continue
                plan.candidates = [
                    password,
                    *(candidate for candidate in plan.candidates if candidate != password),
                ]

    @staticmethod
    def _confirmation_resolution(
        archive_key: str,
        password: str,
        fingerprint_key: str,
        fact_bag: FactBag | None,
        *,
        candidate_evidence: str = "",
    ) -> PasswordResolution:
        return PasswordResolution(
            password=password,
            status=PasswordResolutionStatus.RESOLVED,
            archive_key=archive_key,
            encrypted=True if PasswordResolver._facts_require_password(fact_bag) else None,
            requires_extraction_confirmation=True,
            fingerprint_key=fingerprint_key,
            candidate_evidence=candidate_evidence,
        )

    @staticmethod
    def _archive_input_for_password_probe(fact_bag: FactBag | None) -> dict | None:
        if fact_bag is None:
            return None
        knowledge = ArchiveKnowledge.from_any(fact_bag.get("archive.knowledge"))
        knowledge_input = knowledge.get("source.password_probe_input")
        if not isinstance(knowledge_input, dict) or not knowledge_input:
            knowledge_input = knowledge.get("source.input")
        if not isinstance(knowledge_input, dict):
            return None
        selected_format = str(
            knowledge.get("inspection.summary.format", "")
            or knowledge_input.get("format_hint", "")
            or knowledge.get("source.input.format_hint", "")
            or fact_bag.get("archive.format_hint")
            or ""
        ).strip().lower().lstrip(".")
        if selected_format in {"zip", "rar", "7z"}:
            return {**knowledge_input, "format_hint": selected_format}
        return knowledge_input

    def _remember(
        self,
        archive_key: str,
        password: str | None,
        status: PasswordResolutionStatus,
        test_result: object = None,
        error_text: str = "",
        encrypted: bool | None = None,
        remember_only_on_success: bool = False,
    ) -> PasswordResolution:
        if not remember_only_on_success or password is not None:
            self.password_session.set_resolved(archive_key, password)
        return PasswordResolution(
            password=password,
            status=status,
            test_result=test_result,
            error_text=error_text,
            archive_key=archive_key,
            encrypted=encrypted,
        )

    def _remember_search(
        self,
        archive_key: str,
        search: PasswordSearchResult,
        *,
        encrypted: bool | None,
    ) -> PasswordResolution:
        status = {
            PasswordSearchStatus.FOUND: PasswordResolutionStatus.RESOLVED,
            PasswordSearchStatus.EXHAUSTED: PasswordResolutionStatus.CANDIDATES_EXHAUSTED,
            PasswordSearchStatus.DAMAGED: PasswordResolutionStatus.DAMAGED,
            PasswordSearchStatus.UNSUPPORTED: PasswordResolutionStatus.UNSUPPORTED,
            PasswordSearchStatus.BACKEND_UNAVAILABLE: PasswordResolutionStatus.BACKEND_ERROR,
            PasswordSearchStatus.INCONCLUSIVE: PasswordResolutionStatus.INCONCLUSIVE,
            PasswordSearchStatus.STOPPED: PasswordResolutionStatus.INCONCLUSIVE,
        }[search.status]
        return self._remember(
            archive_key,
            search.password,
            status=status,
            test_result=search.test_result,
            error_text=search.error_text,
            encrypted=encrypted,
            remember_only_on_success=True,
        )

    @staticmethod
    def _facts_confirm_unencrypted(fact_bag: FactBag | None) -> bool:
        health = PasswordResolver._resource_health(fact_bag)
        return bool(
            isinstance(health, dict)
            and health.get("is_archive")
            and not health.get("is_encrypted")
            and not health.get("is_wrong_password")
        )

    @staticmethod
    def _facts_require_password(fact_bag: FactBag | None) -> bool:
        health = PasswordResolver._resource_health(fact_bag)
        return bool(isinstance(health, dict) and (health.get("is_encrypted") or health.get("is_wrong_password")))

    @staticmethod
    def _resource_health(fact_bag: FactBag | None) -> dict:
        if fact_bag is None:
            return {}
        direct = fact_bag.get("resource.health")
        if isinstance(direct, dict):
            return direct
        health = ArchiveKnowledge.from_any(fact_bag.get("archive.knowledge")).get("resource.health")
        return health if isinstance(health, dict) else {}

    @staticmethod
    def _archive_key_from_fact_bag(fact_bag: FactBag | None) -> str:
        if fact_bag is None:
            return ""
        knowledge = ArchiveKnowledge.from_any(fact_bag.get("archive.knowledge"))
        source_derivation = knowledge.get("source.derivation") or {}
        if isinstance(source_derivation, dict):
            return str(source_derivation.get("candidate_logical_name") or source_derivation.get("candidate_entry_path") or "")
        source_input = knowledge.get("source.input") or {}
        return str(source_input.get("logical_name") or source_input.get("entry_path") or "") if isinstance(source_input, dict) else ""

    @staticmethod
    def _facts_have_patches(fact_bag: FactBag | None) -> bool:
        if fact_bag is None:
            return False
        state_payload = ArchiveKnowledge.from_any(fact_bag.get("archive.knowledge")).get("archive.state") or {}
        if isinstance(state_payload, dict):
            return bool(state_payload.get("patches") or state_payload.get("patch_stack") or [])
        return False
