import json
from pathlib import Path
from typing import Any


def load_json_cases(cases_dir: Path) -> list[dict[str, Any]]:
    cases = []
    for path in sorted(cases_dir.glob("*.json")):
        with path.open("r", encoding="utf-8") as handle:
            case = json.load(handle)
        case.setdefault("name", path.stem)
        case["_case_path"] = str(path)
        cases.append(case)
    return cases


def case_id(case: dict[str, Any]) -> str:
    return case.get("name") or Path(case["_case_path"]).stem

