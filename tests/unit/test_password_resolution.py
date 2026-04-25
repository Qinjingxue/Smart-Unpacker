from types import SimpleNamespace

from smart_unpacker.extraction.internal.password_resolution import PasswordResolver
from smart_unpacker.contracts.detection import FactBag


class FakePasswordManager:
    def __init__(self, passwords):
        self.passwords = passwords
        self.no_password_tests = 0
        self.password_searches = 0
        self.no_password_result = SimpleNamespace(returncode=0)
        self.no_password_error = ""
        self.password_result = SimpleNamespace(returncode=0)

    def test_without_password(self, archive_path):
        self.no_password_tests += 1
        return self.no_password_result, self.no_password_error

    def find_working_password(self, archive_path):
        self.password_searches += 1
        return "secret", self.password_result, ""


def test_validation_fact_confirming_unencrypted_skips_password_work():
    manager = FakePasswordManager(passwords=["secret"])
    bag = FactBag()
    bag.set("file.validation_ok", True)
    bag.set("file.validation_encrypted", False)

    resolution = PasswordResolver(manager).resolve("archive.zip", bag)

    assert resolution.password == ""
    assert manager.no_password_tests == 0
    assert manager.password_searches == 0


def test_no_password_success_uses_empty_password_before_searching_passwords():
    manager = FakePasswordManager(passwords=["secret"])

    resolution = PasswordResolver(manager).resolve("archive.zip")

    assert resolution.password == ""
    assert manager.no_password_tests == 1
    assert manager.password_searches == 0


def test_encrypted_no_password_failure_enters_password_search():
    manager = FakePasswordManager(passwords=["secret"])
    manager.no_password_result = SimpleNamespace(returncode=2)
    manager.no_password_error = "Cannot open encrypted archive. Wrong password?"

    resolution = PasswordResolver(manager).resolve("archive.zip")

    assert resolution.password == "secret"
    assert manager.no_password_tests == 1
    assert manager.password_searches == 1


def test_archive_damage_does_not_enter_password_search():
    manager = FakePasswordManager(passwords=["secret"])
    manager.no_password_result = SimpleNamespace(returncode=2)
    manager.no_password_error = "Unexpected end of archive"

    resolution = PasswordResolver(manager).resolve("archive.zip")

    assert resolution.password is None
    assert "unexpected end of archive" in resolution.error_text.lower()
    assert manager.no_password_tests == 1
    assert manager.password_searches == 0
