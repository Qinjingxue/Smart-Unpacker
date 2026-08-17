from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import sys

import pytest


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PE resource APIs are required")


def _manifest_embedder():
    script = Path(__file__).resolve().parents[2] / "scripts" / "embed_windows_manifest.py"
    spec = importlib.util.spec_from_file_location("embed_windows_manifest", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_embedder_replaces_manifest_with_per_monitor_v2_content(tmp_path):
    embedder = _manifest_embedder()
    target = tmp_path / "python-copy.exe"
    shutil.copy2(sys.executable, target)
    manifest = (Path(__file__).resolve().parents[2] / "sunpack.manifest").read_bytes()

    embedder.embed_manifest(target, manifest)

    embedded = embedder.read_manifest(target).decode("utf-8-sig")
    assert "<dpiAwareness" in embedded
    assert "PerMonitorV2" in embedded
