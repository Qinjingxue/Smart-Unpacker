from __future__ import annotations

from typing import Any

from sunpack.repair.model.formats import normalize_format_name


class UnsupportedDiagnosisGraphFormat(ValueError):
    pass


def get_diagnosis_graph_plugin(format_name: str) -> Any:
    normalized = normalize_format_name(format_name)
    if normalized == "zip":
        from sunpack.repair.model.diagnosis.zip_graph import ZipDiagnosisGraphPlugin

        return ZipDiagnosisGraphPlugin()
    if normalized == "7z":
        from sunpack.repair.model.diagnosis.seven_zip_graph import SevenZipDiagnosisGraphPlugin

        return SevenZipDiagnosisGraphPlugin()
    raise UnsupportedDiagnosisGraphFormat(f"diagnosis graph format is not supported yet: {format_name}")
