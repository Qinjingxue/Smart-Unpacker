import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ArchiveScanCase:
    name: str
    case_dir: Path
    manifest_path: Path
    files_dir: Path
    manifest: dict[str, Any]


def load_archive_scan_cases(cases_root: Path) -> list[ArchiveScanCase]:
    cases: list[ArchiveScanCase] = []
    if not cases_root.exists():
        return cases

    for manifest_path in sorted(cases_root.glob("*/case.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("enabled", True) is False:
            continue
        case_dir = manifest_path.parent
        files_dir = case_dir / manifest.get("files_dir", "files")
        if not files_dir.is_dir():
            raise FileNotFoundError(f"Missing files directory for archive scan case: {files_dir}")
        cases.append(ArchiveScanCase(
            name=manifest.get("name") or case_dir.name,
            case_dir=case_dir,
            manifest_path=manifest_path,
            files_dir=files_dir,
            manifest=manifest,
        ))
    return cases


def archive_scan_case_id(case: ArchiveScanCase) -> str:
    return case.name


def materialize_archive_scan_case(case: ArchiveScanCase, workspace: Path) -> Path:
    target = workspace / case.case_dir.name
    shutil.copytree(case.files_dir, target)
    return target
