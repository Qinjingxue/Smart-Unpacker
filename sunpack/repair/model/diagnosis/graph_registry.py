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
    semantic_plugins = {
        "rar": "rar_graph",
        "tar": "tar_graph",
        "gzip": "gzip_graph",
        "bzip2": "bzip2_graph",
        "xz": "xz_graph",
        "zstd": "zstd_graph",
    }
    module_name = semantic_plugins.get(normalized)
    if module_name:
        from importlib import import_module

        module = import_module(f"sunpack.repair.model.diagnosis.{module_name}")
        return module.get_diagnosis_graph_plugin()
    raise UnsupportedDiagnosisGraphFormat(f"diagnosis graph format is not supported yet: {format_name}")
