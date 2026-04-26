from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.passwords.archive_tester import ArchivePasswordTester
from smart_unpacker.passwords.internal.error_signals import has_archive_damage_signals, has_definite_wrong_password
from smart_unpacker.passwords.result import PasswordResolution
from smart_unpacker.passwords.session import PasswordSession


class PasswordResolver:
    def __init__(
        self,
        password_tester: ArchivePasswordTester,
        password_session: PasswordSession | None = None,
    ):
        self.password_tester = password_tester
        self.password_session = password_session or PasswordSession()

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

        if not self.password_tester.passwords:
            return self._remember(archive_key, "", encrypted=False)

        test_result, error_text = self.password_tester.test_without_password(archive_path, part_paths=part_paths)
        if test_result.returncode == 0:
            return self._remember(archive_key, "", test_result=test_result, encrypted=False)

        if has_definite_wrong_password(error_text) or "cannot open encrypted archive" in error_text:
            password, result, error = self.password_tester.find_working_password(archive_path, part_paths=part_paths)
            return self._remember(
                archive_key,
                password,
                test_result=result,
                error_text=error,
                encrypted=True,
                remember_only_on_success=True,
            )

        password, result, error = self.password_tester.find_working_password(archive_path, part_paths=part_paths)
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
        return bool(fact_bag.get("file.validation_ok")) and not bool(fact_bag.get("file.validation_encrypted"))

    @staticmethod
    def _archive_key_from_fact_bag(fact_bag: FactBag | None) -> str:
        if fact_bag is None:
            return ""
        return str(fact_bag.get("candidate.logical_name") or fact_bag.get("candidate.entry_path") or "")
