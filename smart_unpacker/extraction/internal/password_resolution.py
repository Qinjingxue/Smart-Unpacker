from dataclasses import dataclass
from typing import Optional

from smart_unpacker.extraction.internal.errors import has_archive_damage_signals, has_definite_wrong_password
from smart_unpacker.extraction.internal.password_manager import PasswordManager
from smart_unpacker.contracts.detection import FactBag


@dataclass
class PasswordResolution:
    password: Optional[str]
    test_result: object = None
    error_text: str = ""


class PasswordResolver:
    def __init__(self, password_manager: PasswordManager):
        self.password_manager = password_manager

    def resolve(self, archive_path: str, fact_bag: FactBag | None = None, part_paths: list[str] | None = None) -> PasswordResolution:
        if self._facts_confirm_unencrypted(fact_bag):
            return PasswordResolution(password="")

        if not self.password_manager.passwords:
            return PasswordResolution(password="")

        test_result, error_text = self.password_manager.test_without_password(archive_path, part_paths=part_paths)
        if test_result.returncode == 0:
            return PasswordResolution(password="", test_result=test_result)

        if has_definite_wrong_password(error_text) or "cannot open encrypted archive" in error_text:
            password, result, error = self.password_manager.find_working_password(archive_path, part_paths=part_paths)
            return PasswordResolution(password=password, test_result=result, error_text=error)

        if has_archive_damage_signals(error_text):
            return PasswordResolution(password=None, test_result=test_result, error_text=error_text)

        password, result, error = self.password_manager.find_working_password(archive_path, part_paths=part_paths)
        return PasswordResolution(password=password, test_result=result, error_text=error or error_text)

    @staticmethod
    def _facts_confirm_unencrypted(fact_bag: FactBag | None) -> bool:
        if fact_bag is None:
            return False
        return bool(fact_bag.get("file.validation_ok")) and not bool(fact_bag.get("file.validation_encrypted"))
