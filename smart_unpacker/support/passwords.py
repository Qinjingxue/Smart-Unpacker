from __future__ import annotations


def parse_password_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in (text or "").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def read_password_file(password_file: str) -> list[str]:
    with open(password_file, "r", encoding="utf-8") as f:
        return parse_password_lines(f.read())


def dedupe_passwords(passwords: list[str]) -> list[str]:
    deduped_passwords = []
    seen = set()
    for password in passwords:
        if password not in seen:
            seen.add(password)
            deduped_passwords.append(password)
    return deduped_passwords
