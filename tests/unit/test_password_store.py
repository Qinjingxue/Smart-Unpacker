from types import SimpleNamespace

from sunpack.contracts.detection import FactBag
from sunpack.passwords.job import PasswordJob
from sunpack.passwords.result import PasswordProbeResult, PasswordResolutionStatus
from sunpack.passwords.scheduler import PasswordSearchResult, PasswordSearchStatus
from sunpack.passwords import PasswordResolver, PasswordSession, PasswordStore
from sunpack.passwords.internal.store import MAX_RECENT_PASSWORDS


def test_password_store_orders_user_recent_builtin_and_dedupes():
    store = PasswordStore.from_sources(
        cli_passwords=["cli", "shared"],
        clipboard_passwords=["clip", "builtin"],
        recent_passwords=["recent"],
        builtin_passwords=["builtin", "shared"],
    )

    assert store.candidates(directory_passwords=["dir", "clip"]) == ["recent", "dir", "clip", "cli", "shared", "builtin"]


def test_password_store_remembers_success_at_front():
    store = PasswordStore.from_sources(
        cli_passwords=["cli"],
        recent_passwords=["old", "secret"],
        builtin_passwords=["secret"],
    )

    store.remember_success("secret")

    assert store.recent_passwords == ["secret", "old"]
    assert store.candidates() == ["secret", "old", "cli"]


def test_password_store_bounds_recent_success_history():
    store = PasswordStore.from_sources()
    for index in range(MAX_RECENT_PASSWORDS + 20):
        store.remember_success(f"password-{index}")

    assert len(store.recent_passwords) == MAX_RECENT_PASSWORDS
    assert store.recent_passwords[0] == f"password-{MAX_RECENT_PASSWORDS + 19}"


class FakePasswordTester:
    passwords = ["secret"]

    def __init__(self):
        self.test_without_password_calls = 0
        self.search_calls = 0
        self.password_store = PasswordStore.from_sources(cli_passwords=["secret", "fallback"], builtin_passwords=[])
        self.password_scheduler = FakePasswordScheduler(self)

    def add_recent_password(self, password):
        self.password_store.remember_success(password)

    def test_without_password(self, archive_path, part_paths=None):
        self.test_without_password_calls += 1
        return PasswordProbeResult(status="no_match", message="encrypted")

    def search_passwords(self, job: PasswordJob):
        self.search_calls += 1
        return PasswordSearchResult(password="secret", status=PasswordSearchStatus.FOUND, test_result=SimpleNamespace(returncode=0), error_text="")


class FakeFailingPasswordTester(FakePasswordTester):
    def test_without_password(self, archive_path, part_paths=None):
        self.test_without_password_calls += 1
        return PasswordProbeResult(status="damaged", message="headers error")

    def search_passwords(self, job: PasswordJob):
        self.search_calls += 1
        return PasswordSearchResult(password=None, status=PasswordSearchStatus.EXHAUSTED, test_result=SimpleNamespace(returncode=2), error_text="password rejected")


class FakeDamagedPasswordTester(FakeFailingPasswordTester):
    def search_passwords(self, job: PasswordJob):
        self.search_calls += 1
        return PasswordSearchResult(password=None, status=PasswordSearchStatus.DAMAGED, test_result=SimpleNamespace(returncode=2), error_text="headers error")


class FakePasswordScheduler:
    def __init__(self, tester):
        self.tester = tester

    def run(self, job: PasswordJob):
        return self.tester.search_passwords(job)

    def plan_for_extraction(self, job: PasswordJob):
        return self.tester.search_passwords(job)

    def remember_extraction_success(self, fingerprint_key, password):
        pass

    def remember_extraction_rejection(self, fingerprint_key, password):
        pass


def test_password_resolver_records_archive_password_in_session():
    session = PasswordSession()
    resolver = PasswordResolver(FakePasswordTester(), session)

    result = resolver.resolve("sample.zip", archive_key="archive-key")

    assert result.password == "secret"
    assert result.archive_key == "archive-key"
    assert session.get_resolved("archive-key") == "secret"


def test_password_resolver_trusts_unencrypted_resource_health_without_retesting():
    bag = FactBag()
    bag.set("resource.health", {
        "is_archive": True,
        "is_encrypted": False,
        "is_wrong_password": False,
    })
    tester = FakePasswordTester()
    session = PasswordSession()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", fact_bag=bag, archive_key="archive-key")

    assert result.password == ""
    assert result.encrypted is False
    assert session.get_resolved("archive-key") == ""
    assert tester.test_without_password_calls == 0
    assert tester.search_calls == 0
    assert result.archive_key == "archive-key"


def test_password_resolver_trusts_encrypted_resource_health_without_empty_password_test():
    bag = FactBag()
    bag.set("resource.health", {
        "is_archive": True,
        "is_encrypted": True,
        "is_wrong_password": False,
    })
    tester = FakePasswordTester()
    session = PasswordSession()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", fact_bag=bag, archive_key="archive-key")

    assert result.password == "secret"
    assert tester.test_without_password_calls == 0
    assert tester.search_calls == 1


def test_password_resolver_does_not_recheck_clear_wrong_password_after_encrypted_search():
    bag = FactBag()
    bag.set("resource.health", {
        "is_archive": True,
        "is_encrypted": True,
        "is_wrong_password": False,
    })
    tester = FakeFailingPasswordTester()
    session = PasswordSession()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", fact_bag=bag, archive_key="archive-key")

    assert result.password is None
    assert result.status == PasswordResolutionStatus.CANDIDATES_EXHAUSTED
    assert tester.search_calls == 1
    assert tester.test_without_password_calls == 0


def test_password_resolver_preserves_fast_damage_result_without_full_retest():
    bag = FactBag()
    bag.set("resource.health", {
        "is_archive": True,
        "is_encrypted": True,
        "is_wrong_password": False,
    })
    tester = FakeDamagedPasswordTester()
    session = PasswordSession()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", fact_bag=bag, archive_key="archive-key")

    assert result.password is None
    assert result.status == PasswordResolutionStatus.DAMAGED
    assert result.error_text == "headers error"
    assert tester.search_calls == 1
    assert tester.test_without_password_calls == 0


def test_password_resolver_reuses_session_password_without_retesting():
    session = PasswordSession()
    session.set_resolved("archive-key", "secret")
    tester = FakePasswordTester()
    resolver = PasswordResolver(tester, session)

    result = resolver.resolve("sample.zip", archive_key="archive-key")

    assert result.password == "secret"


def test_password_resolver_queues_all_inconclusive_sources_for_extraction_confirmation():
    tester = FakePasswordTester()
    tester.password_store = PasswordStore.from_sources(
        cli_passwords=["user-password"],
        builtin_passwords=["builtin-password"],
    )
    tester.passwords = tester.password_store.candidates()
    planned = []

    class QueueScheduler:
        def plan_for_extraction(self, job):
            candidates = tuple(candidate.value for candidate in job.candidate_pipeline())
            planned.extend(candidates)
            return PasswordSearchResult(
                password=None,
                status=PasswordSearchStatus.INCONCLUSIVE,
                extraction_candidates=candidates,
            )

        def remember_extraction_success(self, fingerprint_key, password):
            pass

        def remember_extraction_rejection(self, fingerprint_key, password):
            pass

    session = PasswordSession()
    resolver = PasswordResolver(tester, session, QueueScheduler())

    first = resolver.resolve("large.rar", archive_key="archive-key")
    resolver.reject_extraction_candidate(first)
    second = resolver.resolve("large.rar", archive_key="archive-key")

    assert planned == ["user-password", "builtin-password"]
    assert first.password == "user-password"
    assert second.password == "builtin-password"
    assert first.requires_extraction_confirmation is True
    assert second.requires_extraction_confirmation is True
    assert tester.test_without_password_calls == 0
    assert session.has_resolved("archive-key") is False

    resolver.confirm_extraction(second)

    assert session.get_resolved("archive-key") == "builtin-password"
    assert tester.password_store.recent_passwords == ["builtin-password"]


def test_password_resolver_uses_directory_passwords_before_user_and_builtin():
    tester = FakePasswordTester()
    tester.password_store = PasswordStore.from_sources(
        cli_passwords=["user-password"],
        clipboard_passwords=["clipboard-password"],
        builtin_passwords=["builtin-password"],
    )
    planned = []

    class QueueScheduler:
        def plan_for_extraction(self, job):
            candidates = tuple(candidate.value for candidate in job.candidate_pipeline())
            planned.extend(candidates)
            return PasswordSearchResult(
                password=None,
                status=PasswordSearchStatus.INCONCLUSIVE,
                extraction_candidates=candidates,
            )

        def remember_extraction_success(self, fingerprint_key, password):
            pass

        def remember_extraction_rejection(self, fingerprint_key, password):
            pass

    resolver = PasswordResolver(tester, PasswordSession(), QueueScheduler())

    first = resolver.resolve(
        "large.rar",
        archive_key="archive-key",
        directory_passwords=["directory-password", "user-password"],
    )

    assert planned == ["directory-password", "user-password", "clipboard-password", "builtin-password"]
    assert first.password == "directory-password"


def test_confirmed_password_is_promoted_across_already_planned_archives():
    tester = FakePasswordTester()
    tester.password_store = PasswordStore.from_sources(
        cli_passwords=["wrong-a", "wrong-b", "shared-secret"],
        builtin_passwords=[],
    )

    class QueueScheduler:
        def plan_for_extraction(self, job):
            candidates = tuple(candidate.value for candidate in job.candidate_pipeline())
            return PasswordSearchResult(
                password=None,
                status=PasswordSearchStatus.INCONCLUSIVE,
                extraction_candidates=candidates,
            )

        def remember_extraction_success(self, fingerprint_key, password):
            pass

        def remember_extraction_rejection(self, fingerprint_key, password):
            pass

    resolver = PasswordResolver(tester, PasswordSession(), QueueScheduler())
    archive_a = resolver.resolve("first.unknown", archive_key="first")
    archive_b = resolver.resolve("second.unknown", archive_key="second")
    resolver.reject_extraction_candidate(archive_a)
    archive_a = resolver.resolve("first.unknown", archive_key="first")
    resolver.reject_extraction_candidate(archive_a)
    archive_a = resolver.resolve("first.unknown", archive_key="first")

    resolver.confirm_extraction(archive_a)
    resolver.reject_extraction_candidate(archive_b)
    promoted_b = resolver.resolve("second.unknown", archive_key="second")

    assert archive_a.password == "shared-secret"
    assert promoted_b.password == "shared-secret"


def test_hundreds_of_archives_reuse_batch_success_instead_of_rewalking_password_matrix():
    passwords = [f"wrong-{index}" for index in range(499)] + ["shared-secret"]
    tester = FakePasswordTester()
    tester.password_store = PasswordStore.from_sources(cli_passwords=passwords, builtin_passwords=[])

    class QueueScheduler:
        def plan_for_extraction(self, job):
            candidates = tuple(candidate.value for candidate in job.candidate_pipeline())
            return PasswordSearchResult(
                password=None,
                status=PasswordSearchStatus.INCONCLUSIVE,
                extraction_candidates=candidates,
            )

        def remember_extraction_success(self, fingerprint_key, password):
            pass

        def remember_extraction_rejection(self, fingerprint_key, password):
            pass

    resolver = PasswordResolver(tester, PasswordSession(), QueueScheduler())
    attempts = 0
    resolution = resolver.resolve("archive-0.mixed", archive_key="archive-0")
    while resolution.password != "shared-secret":
        attempts += 1
        resolver.reject_extraction_candidate(resolution)
        resolution = resolver.resolve("archive-0.mixed", archive_key="archive-0")
    attempts += 1
    resolver.confirm_extraction(resolution)

    for index in range(1, 100):
        resolution = resolver.resolve(f"archive-{index}.mixed", archive_key=f"archive-{index}")
        attempts += 1
        assert resolution.password == "shared-secret"
        resolver.confirm_extraction(resolution)

    assert attempts == 599
