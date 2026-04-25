from pathlib import Path


def build_cli_pipeline_fixture(root: Path) -> Path:
    fixture = root / "pipeline_run"
    fixture.mkdir(parents=True, exist_ok=True)
    payload_size = 1024 * 1024 + 128
    (fixture / "rj081295.7z.001").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"x" * payload_size)
    (fixture / "rj081295.7z").write_bytes(b"companion-7z" + b"y" * payload_size)
    (fixture / "rj081295").write_bytes(b"companion-plain" + b"z" * payload_size)
    return fixture
