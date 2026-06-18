from sunpack.contracts.detection import FactBag
from sunpack.contracts.archive_knowledge import ArchiveKnowledge
from sunpack.passwords.candidates import PasswordCandidatePipeline
from sunpack.passwords.job import PasswordJob
from sunpack.passwords.result import PasswordProbeResult, PasswordResolution, PasswordResolutionStatus
from sunpack.passwords.scheduler import PasswordScheduler, PasswordSearchResult, PasswordSearchStatus
from sunpack.passwords.session import PasswordSession


class PasswordResolver:
    def __init__(
        self,
        password_tester,
        password_session: PasswordSession | None = None,
        password_scheduler: PasswordScheduler | None = None,
    ):
        self.password_tester = password_tester
        self.password_session = password_session or PasswordSession()
        self.password_scheduler = password_scheduler or password_tester.password_scheduler

    def resolve(
        self,
        archive_path: str,
        fact_bag: FactBag | None = None,
        part_paths: list[str] | None = None,
        archive_key: str = "",
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

        if not self.password_tester.passwords and self._facts_require_password(fact_bag):
            return PasswordResolution(
                password=None,
                status=PasswordResolutionStatus.PASSWORD_REQUIRED,
                error_text="archive requires a password but no candidates were provided",
                archive_key=archive_key,
                encrypted=True,
            )

        if self._facts_require_password(fact_bag):
            search = self._run_password_search(archive_path, fact_bag=fact_bag, part_paths=part_paths)
            if search.status == PasswordSearchStatus.FOUND:
                return self._remember_search(archive_key, search, encrypted=True)
            if search.status in {PasswordSearchStatus.DAMAGED, PasswordSearchStatus.INCONCLUSIVE}:
                probe = self._test_without_password(
                    archive_path,
                    fact_bag=fact_bag,
                    part_paths=part_paths,
                )
                if probe.status == "damaged":
                    return self._resolution_from_probe(archive_key, probe)
            return self._remember_search(archive_key, search, encrypted=True)

        probe = self._test_without_password(
            archive_path,
            fact_bag=fact_bag,
            part_paths=part_paths,
        )
        if probe.status == "match":
            return self._remember(
                archive_key,
                "",
                status=PasswordResolutionStatus.UNENCRYPTED,
                test_result=probe,
                encrypted=False,
            )

        if probe.status == "no_match":
            if not self.password_tester.passwords:
                return PasswordResolution(
                    password=None,
                    status=PasswordResolutionStatus.PASSWORD_REQUIRED,
                    test_result=probe,
                    error_text=probe.message,
                    archive_key=archive_key,
                    encrypted=True,
                )
            search = self._run_password_search(archive_path, fact_bag=fact_bag, part_paths=part_paths)
            return self._remember_search(archive_key, search, encrypted=True)

        return PasswordResolution(
            password="",
            status=PasswordResolutionStatus.INCONCLUSIVE,
            test_result=probe,
            error_text=probe.message,
            archive_key=archive_key,
            encrypted=None,
        )

    def _run_password_search(self, archive_path: str, fact_bag: FactBag | None = None, part_paths: list[str] | None = None):
        archive_input = self._archive_input_for_password_probe(archive_path, fact_bag, part_paths)
        candidates = PasswordCandidatePipeline.from_password_store(self.password_tester.password_store)
        return self.password_scheduler.run(PasswordJob(
            archive_path=archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
            candidates=candidates,
        ))

    def _test_without_password(
        self,
        archive_path: str,
        *,
        fact_bag: FactBag | None = None,
        part_paths: list[str] | None = None,
    ):
        archive_input = self._archive_input_for_password_probe(archive_path, fact_bag, part_paths)
        if isinstance(archive_input, dict):
            try:
                return self.password_tester.test_without_password(
                    archive_path,
                    part_paths=part_paths,
                    archive_input=archive_input,
                )
            except TypeError as error:
                if "archive_input" not in str(error):
                    raise
        return self.password_tester.test_without_password(archive_path, part_paths=part_paths)

    @staticmethod
    def _archive_input_for_password_probe(
        archive_path: str,
        fact_bag: FactBag | None,
        part_paths: list[str] | None,
    ) -> dict | None:
        if fact_bag is None:
            return None
        knowledge_input = ArchiveKnowledge.from_any(fact_bag.get("archive.knowledge")).get("source.input")
        if isinstance(knowledge_input, dict):
            return knowledge_input
        return None

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

    @staticmethod
    def _facts_confirm_unencrypted(fact_bag: FactBag | None) -> bool:
        health = PasswordResolver._resource_health(fact_bag)
        if isinstance(health, dict):
            if health.get("is_archive") and not health.get("is_encrypted") and not health.get("is_wrong_password"):
                return True
        return False

    @staticmethod
    def _facts_require_password(fact_bag: FactBag | None) -> bool:
        health = PasswordResolver._resource_health(fact_bag)
        if isinstance(health, dict) and (health.get("is_encrypted") or health.get("is_wrong_password")):
            return True
        return False

    def _remember_search(self, archive_key: str, search: PasswordSearchResult, *, encrypted: bool | None) -> PasswordResolution:
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
    def _resolution_from_probe(archive_key: str, probe: PasswordProbeResult) -> PasswordResolution:
        status = {
            "damaged": PasswordResolutionStatus.DAMAGED,
            "unsupported_method": PasswordResolutionStatus.UNSUPPORTED,
            "backend_unavailable": PasswordResolutionStatus.BACKEND_ERROR,
        }.get(probe.status, PasswordResolutionStatus.INCONCLUSIVE)
        return PasswordResolution(
            password=None,
            status=status,
            test_result=probe,
            error_text=probe.message,
            archive_key=archive_key,
        )

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
            patches = state_payload.get("patches") or state_payload.get("patch_stack") or []
            return bool(patches)
        return False
