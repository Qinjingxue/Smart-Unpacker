from pathlib import Path

import pytest

from smart_unpacker.coordinator.reporting import RunReporter
from smart_unpacker.config.schema import normalize_config
from smart_unpacker.postprocess.actions import PostProcessActions
from tests.helpers.assertions import assert_case_expectations
from tests.helpers.case_loader import case_id, load_json_cases
from tests.helpers.fs_builder import build_files


CASES_DIR = Path(__file__).resolve().parents[1] / "cases" / "postprocess"
CASES = load_json_cases(CASES_DIR)


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_postprocess_case(case, case_workspace):
    workspace = build_files(case_workspace, case.get("arrange"))
    run_postprocess_action(case["act"], workspace)
    assert_case_expectations(snapshot_workspace(workspace), case.get("assert", {}))


def test_postprocess_flatten_output_uses_chinese_language(case_workspace, capsys):
    target = case_workspace / "extract_out"
    child = target / "only_child"
    child.mkdir(parents=True)
    (child / "payload.txt").write_text("ok", encoding="utf-8")

    PostProcessActions(normalize_config({}), language="zh").apply(
        cleanup_archives=False,
        flatten_outputs=True,
        flatten_targets=[str(target)],
    )

    output = capsys.readouterr().out
    assert "正在压平单子目录" in output
    assert "Flattening single-branch directories" not in output


def run_postprocess_action(act: dict, workspace: Path):
    action_type = act["type"]
    if action_type == "cleanup":
        archives = [
            [str(workspace / part) for part in archive_parts]
            for archive_parts in act.get("archives", [])
        ]
        config = normalize_config({"post_extract": {"archive_cleanup_mode": act.get("mode", "d")}})
        PostProcessActions(config).apply(
            cleanup_archives=True,
            flatten_outputs=False,
            archives_to_clean=archives,
        )
        return
    if action_type == "flatten":
        PostProcessActions(normalize_config({})).apply(
            cleanup_archives=False,
            flatten_outputs=True,
            flatten_targets=[str(workspace / act["target"])],
        )
        return
    if action_type == "failed_log":
        RunReporter().log_final_summary(
            str(workspace),
            0,
            act.get("success_count", 0),
            act.get("failed_tasks", []),
        )
        return
    raise ValueError(f"Unsupported postprocess action: {action_type}")


def snapshot_workspace(workspace: Path) -> dict:
    files = {}
    exists = {}
    for path in workspace.rglob("*"):
        relative = path.relative_to(workspace).as_posix()
        exists[relative] = path.exists()
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            files[relative] = {
                "text": text,
                "lines": text.splitlines(),
            }

    for relative in [
        "dummy_archive.zip",
        "extracted_dir/game_data.bin",
        "extracted_dir/config.ini",
        "extracted_dir/only_child_folder",
        "failed_log.txt",
    ]:
        exists.setdefault(relative, (workspace / relative).exists())
    return {"exists": exists, "files": files}
