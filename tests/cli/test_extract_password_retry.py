import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from sunpack.cli.cli_context import CliContext
from sunpack.cli.cli_reporter import CliReporter
from sunpack.cli.commands import extract
from sunpack.contracts.failures import FailureInfo, FailureKind
from sunpack.cli.cli_runtime import build_password_summary
from tests.helpers.fake_pipeline_engine import FakePipelineEngine


def test_wrong_password_failure_detection():
    wrong = FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "rejected")
    damaged = FailureInfo(FailureKind.DAMAGED, "extraction", "damaged", repairable=True)
    assert extract.has_password_failure([wrong]) is True
    assert extract.has_password_failure([damaged]) is False


def test_extract_config_combines_clipboard_passwords_for_engine():
    password_summary = build_password_summary(
        ["cli-secret", "shared-secret"],
        use_builtin_passwords=False,
        clipboard_passwords=["clipboard-secret", "shared-secret"],
    )
    config = extract._extract_run_config({}, password_summary)

    assert config["user_passwords"] == ["cli-secret", "shared-secret", "clipboard-secret"]


def test_extract_prompts_for_password_retry_after_wrong_password(tmp_path, monkeypatch):
    target = tmp_path / "archives"
    target.mkdir()
    attempts = []

    class FakeRunner:
        def __init__(self, config):
            attempts.append(list(config.get("user_passwords", [])))
            self.recent_passwords = []

        def run_targets(self, _target_paths):
            if len(attempts) == 1:
                return SimpleNamespace(
                    success_count=0,
                    failed_tasks=["secret.zip [密码错误]"],
                    processed_keys=["secret"],
                    failures=[FailureInfo(FailureKind.WRONG_PASSWORD, "password_resolution", "密码错误")],
                )
            self.recent_passwords = ["secret"]
            return SimpleNamespace(success_count=1, failed_tasks=[], processed_keys=["secret"], failures=[])

    answers = iter(["y", "secret", ""])
    monkeypatch.setattr(extract, "pipeline_engine", lambda _config: FakePipelineEngine(FakeRunner))
    monkeypatch.setattr(extract, "collect_clipboard_passwords", lambda _config: [])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    args = SimpleNamespace(
        paths=[str(target)],
        password=[],
        password_file=None,
        prompt_passwords=False,
        no_builtin_passwords=True,
        recursive_extract=None,
        worker_profile=None,
        archive_cleanup_mode=None,
        flatten_single_directory=None,
        json=False,
        quiet=False,
        verbose=False,
    )
    ctx = CliContext(language="en", reporter=CliReporter())

    exit_code, result = asyncio.run(extract.handle(args, ctx))

    assert exit_code == 0
    assert attempts == [[], ["secret"]]
    assert result.summary["password_retry_count"] == 1
    assert result.summary["success_count"] == 1
    assert result.errors == []


def test_extract_verbose_prints_partial_recovery_file_details(tmp_path, monkeypatch, capsys):
    target = tmp_path / "archives"
    target.mkdir()
    report = tmp_path / "recovery_report.json"
    report.write_text(
        """{
          "files": [
            {"archive_path": "good.txt", "status": "complete", "bytes_written": 2, "expected_size": 2, "user_action": "safe_to_use"},
            {"archive_path": "partial.bin", "status": "partial", "bytes_written": 4, "expected_size": 8, "user_action": "inspect_manually"}
          ]
        }""",
        encoding="utf-8",
    )

    class FakeRunner:
        recent_passwords = []

        def __init__(self, _config):
            pass

        def run_targets(self, _target_paths):
            return SimpleNamespace(
                success_count=0,
                failed_tasks=[],
                processed_keys=["broken"],
                failures=[],
                partial_success_count=1,
                recovered_outputs=[{"archive": "broken.zip", "recovery_report": str(report)}],
            )

    monkeypatch.setattr(extract, "pipeline_engine", lambda _config: FakePipelineEngine(FakeRunner))
    monkeypatch.setattr(extract, "collect_clipboard_passwords", lambda _config: [])
    args = SimpleNamespace(
        paths=[str(target)],
        password=[],
        password_file=None,
        prompt_passwords=False,
        no_builtin_passwords=True,
        recursive_extract=None,
        worker_profile=None,
        archive_cleanup_mode=None,
        flatten_single_directory=None,
        json=False,
        quiet=False,
        verbose=True,
        allow_partial=True,
    )
    ctx = CliContext(language="en", reporter=CliReporter(verbose=True))

    exit_code, result = asyncio.run(extract.handle(args, ctx))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert result.summary["partial_success_count"] == 1
    assert "[complete] good.txt 2/2 B" in captured.out
    assert "[partial] partial.bin 4/8 B" in captured.out


def test_extract_normal_mode_keeps_partial_file_details_out_of_console(tmp_path, monkeypatch, capsys):
    target = tmp_path / "archives"
    target.mkdir()
    report = tmp_path / "recovery_report.json"
    report.write_text(
        """{
          "archive_coverage": {"completeness": 0.5, "expected_files": 2, "complete_files": 1, "failed_files": 1},
          "archive_state": {"patch_digest": "abc", "patch_stack": [{"id": "crop"}]},
          "files": [
            {"archive_path": "good.txt", "status": "complete", "bytes_written": 2, "expected_size": 2, "user_action": "safe_to_use"},
            {"archive_path": "bad.bin", "status": "failed", "failure_kind": "checksum_error", "user_action": "not_recovered"}
          ]
        }""",
        encoding="utf-8",
    )

    class FakeRunner:
        recent_passwords = []

        def __init__(self, _config):
            pass

        def run_targets(self, _target_paths):
            return SimpleNamespace(
                success_count=0,
                failed_tasks=[],
                processed_keys=["broken"],
                failures=[],
                partial_success_count=1,
                recovered_outputs=[{
                    "archive": "broken.zip",
                    "recovery_report": str(report),
                    "archive_coverage": {"completeness": 0.5},
                }],
            )

    monkeypatch.setattr(extract, "pipeline_engine", lambda _config: FakePipelineEngine(FakeRunner))
    monkeypatch.setattr(extract, "collect_clipboard_passwords", lambda _config: [])
    args = SimpleNamespace(
        paths=[str(target)],
        password=[],
        password_file=None,
        prompt_passwords=False,
        no_builtin_passwords=True,
        recursive_extract=None,
        worker_profile=None,
        archive_cleanup_mode=None,
        flatten_single_directory=None,
        json=False,
        quiet=False,
        verbose=False,
        allow_partial=True,
    )
    ctx = CliContext(language="en", reporter=CliReporter(verbose=False))

    exit_code, result = asyncio.run(extract.handle(args, ctx))

    captured = capsys.readouterr()
    assert exit_code == 0
    assert result.summary["partial_success_count"] == 1
    assert result.summary["recovered_outputs"][0]["recovery_report"] == str(report)
    assert "[partial]" not in captured.out
    assert "bad.bin" not in captured.out


def test_extract_json_schema_includes_partial_recovery_contract(tmp_path, monkeypatch, capsys):
    target = tmp_path / "archives"
    target.mkdir()
    report = tmp_path / "recovery_report.json"
    report.write_text(
        """{
          "version": 1,
          "success_kind": "partial",
          "archive_coverage": {
            "completeness": 0.5,
            "expected_files": 2,
            "complete_files": 1,
            "failed_files": 1,
            "sources": [{"method": "archive_test_crc"}]
          },
          "archive_state": {"patch_digest": "abc", "patch_stack": [{"id": "crop"}]},
          "files": [
            {"archive_path": "good.txt", "status": "complete", "bytes_written": 2, "user_action": "safe_to_use"},
            {"archive_path": "bad.bin", "status": "failed", "failure_kind": "checksum_error", "user_action": "not_recovered"}
          ]
        }""",
        encoding="utf-8",
    )

    class FakeRunner:
        recent_passwords = ["secret"]

        def __init__(self, _config):
            pass

        def run_targets(self, _target_paths):
            return SimpleNamespace(
                success_count=0,
                failed_tasks=[],
                processed_keys=["broken"],
                failures=[],
                partial_success_count=1,
                recovered_outputs=[{
                    "archive": "broken.zip",
                    "out_dir": str(tmp_path / "out"),
                    "assessment_status": "partial",
                    "content_integrity": "payload_damaged",
                    "archive_coverage": {
                        "completeness": 0.5,
                        "expected_files": 2,
                        "complete_files": 1,
                        "failed_files": 1,
                    },
                    "recovery_report": str(report),
                }],
            )

    monkeypatch.setattr(extract, "pipeline_engine", lambda _config: FakePipelineEngine(FakeRunner))
    monkeypatch.setattr(extract, "collect_clipboard_passwords", lambda _config: [])
    args = SimpleNamespace(
        paths=[str(target)],
        password=["secret"],
        password_file=None,
        prompt_passwords=False,
        no_builtin_passwords=True,
        recursive_extract=None,
        worker_profile=None,
        archive_cleanup_mode=None,
        flatten_single_directory=None,
        json=True,
        quiet=False,
        verbose=False,
        allow_partial=True,
    )
    reporter = CliReporter(json_mode=True)
    ctx = CliContext(language="en", reporter=reporter)

    exit_code, result = asyncio.run(extract.handle(args, ctx))
    reporter.emit_result(result)

    payload = json.loads(capsys.readouterr().out)
    recovered = payload["summary"]["recovered_outputs"][0]

    assert exit_code == 0
    assert payload["command"] == "extract"
    assert payload["summary"]["partial_success_count"] == 1
    assert payload["summary"]["password_retry_count"] == 0
    assert recovered["recovery_report"] == str(report)
    assert recovered["archive_coverage"]["completeness"] == 0.5
    assert payload["tasks"][0]["partial_success_count"] == 1
    assert payload["items"][0]["combined_passwords"] == ["secret"]
