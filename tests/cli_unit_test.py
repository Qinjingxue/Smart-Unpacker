import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from smart_unpacker.app.cli import (
    CliReporter,
    build_cli_parser,
    build_password_summary,
    collect_cli_passwords,
    main,
    preprocess_sys_argv,
    resolve_common_root,
)
from smart_unpacker.support.types import CliCommandResult


class CliUnitTest(unittest.TestCase):
    def test_resolve_common_root_with_sibling_files_returns_parent_dir(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            file_a = root / "a.7z"
            file_b = root / "b.zip"
            file_a.write_bytes(b"a")
            file_b.write_bytes(b"b")
            self.assertEqual(resolve_common_root([str(file_a), str(file_b)]), str(root))

    def test_parser_requires_subcommand(self):
        parser = build_cli_parser()
        with self.assertRaises(SystemExit) as exc:
            parser.parse_args([])
        self.assertEqual(exc.exception.code, 2)

    def test_extract_requires_paths(self):
        parser = build_cli_parser()
        with self.assertRaises(SystemExit) as exc:
            parser.parse_args(["extract"])
        self.assertEqual(exc.exception.code, 2)

    def test_collect_cli_passwords_merges_sources_and_dedupes(self):
        args = SimpleNamespace(
            password=["123", "abc", "123"],
            password_file=None,
            prompt_passwords=False,
        )
        self.assertEqual(collect_cli_passwords(args), ["123", "abc"])

    def test_collect_cli_passwords_uses_terminal_prompt_when_requested(self):
        args = SimpleNamespace(
            password=["seed"],
            password_file=None,
            prompt_passwords=True,
        )
        with patch("smart_unpacker.app.cli.prompt_passwords_terminal", return_value=["x", "y"]) as prompt:
            self.assertEqual(collect_cli_passwords(args), ["x", "y"])
            prompt.assert_called_once_with(["seed"])

    @patch("smart_unpacker.app.cli.ResourceLocator")
    def test_password_summary_preserves_source_priority(self, mock_locator):
        mock_locator.return_value.get_builtin_passwords.return_value = ["123456", "123", "0000", "789"]
        summary = build_password_summary(["123", "456"], use_builtin_passwords=True, recent_passwords=["456", "789"])
        self.assertEqual(summary.combined_passwords, ["123", "456", "789", "123456", "0000"])

    def test_preprocess_sys_argv_fixes_windows_context_menu_escaping(self):
        argv_with_prompt = ['D:\\Folder" --prompt-passwords --pause-on-exit']
        self.assertEqual(
            preprocess_sys_argv(argv_with_prompt),
            ["D:\\Folder", "--prompt-passwords", "--pause-on-exit"],
        )

        argv_without_prompt = ['D:\\Folder"']
        self.assertEqual(preprocess_sys_argv(argv_without_prompt), ["D:\\Folder"])

        argv_normal = ["extract", "C:\\Path\\To\\File.zip", "--prompt-passwords"]
        self.assertEqual(preprocess_sys_argv(argv_normal), argv_normal)

    @patch("smart_unpacker.app.cli.DecompressionEngine")
    def test_extract_with_no_builtin_passwords_flag_disables_it_in_engine(self, mock_engine):
        with tempfile.TemporaryDirectory() as td:
            archive_path = Path(td) / "demo.zip"
            archive_path.write_bytes(b"demo")
            mock_instance = mock_engine.return_value
            mock_instance.run.return_value = SimpleNamespace(success_count=1, failed_tasks=[], processed_keys=["demo"])
            self.assertEqual(main(["extract", str(archive_path), "--no-builtin-passwords"]), 0)
            self.assertFalse(mock_engine.call_args[1].get("use_builtin_passwords", True))

    @patch("smart_unpacker.app.cli.DecompressionEngine")
    def test_extract_returns_one_when_failed_tasks_exist(self, mock_engine):
        with tempfile.TemporaryDirectory() as td:
            archive_path = Path(td) / "demo.zip"
            archive_path.write_bytes(b"demo")
            mock_instance = mock_engine.return_value
            mock_instance.run.return_value = SimpleNamespace(success_count=0, failed_tasks=["demo [密码错误]"], processed_keys=[])
            self.assertEqual(main(["extract", str(archive_path)]), 1)

    @patch("smart_unpacker.app.cli.DecompressionEngine")
    def test_scan_uses_readonly_path(self, mock_engine):
        with tempfile.TemporaryDirectory() as td:
            archive_path = Path(td) / "demo.zip"
            archive_path.write_bytes(b"demo")
            mock_instance = mock_engine.return_value
            mock_instance.scan_archives_readonly.return_value = []
            self.assertEqual(main(["scan", str(archive_path)]), 0)
            mock_instance.scan_archives_readonly.assert_called_once()
            mock_instance.run.assert_not_called()

    @patch("smart_unpacker.app.cli.DecompressionEngine")
    def test_inspect_json_output_contains_validation_skipped(self, mock_engine):
        with tempfile.TemporaryDirectory() as td:
            archive_path = Path(td) / "demo.7z"
            archive_path.write_bytes(b"demo")
            mock_instance = mock_engine.return_value
            from smart_unpacker.support.types import InspectionResult

            mock_instance._resolve_scene_context_for_path.return_value = None
            mock_instance.root_dir = td
            mock_instance._build_directory_relationships.return_value = {
                archive_path.name: None,
            }
            mock_instance.inspect_archive_candidate.return_value = InspectionResult(
                path=str(archive_path),
                decision="archive",
                should_extract=True,
                ext=".7z",
                detected_ext=".7z",
                validation_ok=False,
                validation_skipped=True,
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = main(["inspect", str(archive_path), "--json"])
            self.assertEqual(exit_code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertTrue(payload["items"][0]["validation_skipped"])

    @patch("smart_unpacker.app.cli.ResourceLocator")
    def test_passwords_json_output_is_machine_readable(self, mock_locator):
        mock_locator.return_value.get_builtin_passwords.return_value = ["123456", "123", "0000", "789"]
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            exit_code = main(["passwords", "-p", "123", "--json"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["command"], "passwords")
        self.assertEqual(payload["summary"]["combined_password_count"], 4)
        self.assertEqual(payload["items"][0]["combined_passwords"], ["123", "123456", "0000", "789"])

    def test_cli_reporter_uses_flush_for_terminal_output(self):
        reporter = CliReporter(json_mode=False, quiet=False, verbose=True)
        with patch("builtins.print") as mock_print:
            reporter.info("info")
            reporter.detail("detail")
            reporter.error("error")
        self.assertEqual(mock_print.call_args_list[0].kwargs.get("flush"), True)
        self.assertEqual(mock_print.call_args_list[1].kwargs.get("flush"), True)
        self.assertEqual(mock_print.call_args_list[2].kwargs.get("flush"), True)

    def test_cli_reporter_flushes_json_result(self):
        reporter = CliReporter(json_mode=True, quiet=False, verbose=False)
        with patch("builtins.print") as mock_print:
            reporter.emit_result(CliCommandResult(command="inspect", inputs={}, summary={}))
        self.assertEqual(mock_print.call_args.kwargs.get("flush"), True)

    def test_register_context_menu_script_uses_extract_subcommand(self):
        script_path = Path(REPO_ROOT) / "scripts" / "register_context_menu.ps1"
        content = script_path.read_text(encoding="utf-8")
        self.assertIn('extract "{1}" --prompt-passwords --pause-on-exit', content)
        self.assertIn('extract "{2}" --prompt-passwords --pause-on-exit', content)


if __name__ == "__main__":
    unittest.main()
