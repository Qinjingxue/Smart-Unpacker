from __future__ import annotations

import importlib
from typing import Any

from repair_training.core.plugin import normalize_format_name


class UnsupportedDiagnosisGraphFormat(ValueError):
    pass


def get_diagnosis_graph_plugin(format_name: str) -> Any:
    normalized = normalize_format_name(format_name)
    if normalized != "zip":
        raise UnsupportedDiagnosisGraphFormat(f"diagnosis graph format is not supported yet: {format_name}")
    module = importlib.import_module("repair_training.formats.zip.diagnosis_graph")
    factory = getattr(module, "get_diagnosis_graph_plugin", None)
    if not callable(factory):
        raise UnsupportedDiagnosisGraphFormat("ZIP diagnosis graph plugin is missing get_diagnosis_graph_plugin()")
    return factory()
