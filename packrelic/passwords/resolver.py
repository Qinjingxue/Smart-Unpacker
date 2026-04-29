from packrelic.contracts.detection import FactBag
from packrelic.contracts.archive_state import ArchiveState
from packrelic.passwords.candidates import PasswordCandidatePipeline
from packrelic.passwords.job import PasswordJob
from packrelic.passwords.result import PasswordResolution
from packrelic.passwords.scheduler import PasswordScheduler
from packrelic.passwords.session import PasswordSession
from packrelic.support.archive_error_signals import has_archive_damage_signals, has_definite_wrong_password


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
                archive_key=archive_key,
            )

        if self._facts_confirm_unencrypted(fact_bag):
            return self._remember(archive_key, "", encrypted=False)

        if self._facts_have_patches(fact_bag) and self._facts_require_password(fact_bag):
            return PasswordResolution(
                password=None,
                error_text="password verification is unsupported for patched archive state without a resolved password",
                archive_key=archive_key,
                encrypted=True,
            )

        if not self.password_tester.passwords:
            return self._remember(archive_key, "", encrypted=False)

        if self._facts_require_password(fact_bag):
            search = self._run_password_search(archive_path, fact_bag=fact_bag, part_paths=part_paths)
            password, result, error = search.password, search.test_result, search.error_text
            if password is None and self._should_recheck_failed_encrypted_search(error):
                test_result, error_text = self._test_without_password(
                    archive_path,
                    fact_bag=fact_bag,
                    part_paths=part_paths,
                )
                if has_archive_damage_signals(error_text) and not has_definite_wrong_password(error_text):
                    return PasswordResolution(
                        password=None,
                        test_result=test_result,
                        error_text=error_text,
                        archive_key=archive_key,
                    )
            return self._remember(
                archive_key,
                password,
                test_result=result,
                error_text=error,
                encrypted=True,
                remember_only_on_success=True,
            )

        test_result, error_text = self._test_without_password(
            archive_path,
            fact_bag=fact_bag,
            part_paths=part_paths,
        )
        if test_result.returncode == 0:
            return self._remember(archive_key, "", test_result=test_result, encrypted=False)

        if has_definite_wrong_password(error_text) or "cannot open encrypted archive" in error_text:
            search = self._run_password_search(archive_path, fact_bag=fact_bag, part_paths=part_paths)
            password, result, error = search.password, search.test_result, search.error_text
            return self._remember(
                archive_key,
                password,
                test_result=result,
                error_text=error,
                encrypted=True,
                remember_only_on_success=True,
            )

        search = self._run_password_search(archive_path, fact_bag=fact_bag, part_paths=part_paths)
        password, result, error = search.password, search.test_result, search.error_text
        if password is None and has_archive_damage_signals(error_text):
            return PasswordResolution(
                password=None,
                test_result=test_result,
                error_text=error_text,
                archive_key=archive_key,
            )
        return self._remember(
            archive_key,
            password,
            test_result=result,
            error_text=error or error_text,
            encrypted=True if password else None,
            remember_only_on_success=True,
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
        raw_state = fact_bag.get("archive.state")
        if isinstance(raw_state, dict):
            try:
                state = ArchiveState.from_any(raw_state, archive_path=archive_path, part_paths=part_paths)
            except (TypeError, ValueError):
                return None
            if state.patches:
                return None
            return state.to_archive_input_descriptor().to_dict()
        archive_input = fact_bag.get("archive.input")
        return archive_input if isinstance(archive_input, dict) else None

    def _remember(
        self,
        archive_key: str,
        password: str | None,
        test_result: object = None,
        error_text: str = "",
        encrypted: bool | None = None,
        remember_only_on_success: bool = False,
    ) -> PasswordResolution:
        if not remember_only_on_success or password is not None:
            self.password_session.set_resolved(archive_key, password)
        return PasswordResolution(
            password=password,
            test_result=test_result,
            error_text=error_text,
            archive_key=archive_key,
            encrypted=encrypted,
        )

    @staticmethod
    def _facts_confirm_unencrypted(fact_bag: FactBag | None) -> bool:
        if fact_bag is None:
            return False
        health = fact_bag.get("resource.health") or {}
        if isinstance(health, dict):
            if health.get("is_archive") and not health.get("is_encrypted") and not health.get("is_wrong_password"):
                return True
        return bool(fact_bag.get("file.validation_ok")) and not bool(fact_bag.get("file.validation_encrypted"))

    @staticmethod
    def _facts_require_password(fact_bag: FactBag | None) -> bool:
        if fact_bag is None:
            return False
        health = fact_bag.get("resource.health") or {}
        if isinstance(health, dict) and (health.get("is_encrypted") or health.get("is_wrong_password")):
            return True
        return bool(fact_bag.get("file.validation_encrypted"))

    @staticmethod
    def _should_recheck_failed_encrypted_search(error_text: str) -> bool:
        if has_archive_damage_signals(error_text):
            return True
        return not has_definite_wrong_password(error_text)

    @staticmethod
    def _archive_key_from_fact_bag(fact_bag: FactBag | None) -> str:
        if fact_bag is None:
            return ""
        return str(fact_bag.get("candidate.logical_name") or fact_bag.get("candidate.entry_path") or "")

    @staticmethod
    def _facts_have_patches(fact_bag: FactBag | None) -> bool:
        if fact_bag is None:
            return False
        raw_state = fact_bag.get("archive.state")
        if isinstance(raw_state, dict):
            patches = raw_state.get("patches") or raw_state.get("patch_stack") or []
            return bool(patches)
        return False
