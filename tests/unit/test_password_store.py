from smart_unpacker.passwords import PasswordStore


def test_password_store_orders_user_recent_builtin_and_dedupes():
    store = PasswordStore.from_sources(
        cli_passwords=["cli", "shared"],
        recent_passwords=["recent", "cli"],
        builtin_passwords=["builtin", "shared"],
    )

    assert store.candidates() == ["cli", "shared", "recent", "builtin"]


def test_password_store_remembers_success_at_front():
    store = PasswordStore.from_sources(
        cli_passwords=["cli"],
        recent_passwords=["old", "secret"],
        builtin_passwords=["secret"],
    )

    store.remember_success("secret")

    assert store.recent_passwords == ["secret", "old"]
    assert store.candidates() == ["cli", "secret", "old"]
