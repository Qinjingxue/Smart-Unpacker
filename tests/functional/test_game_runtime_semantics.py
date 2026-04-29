from pathlib import Path

import pytest

from packrelic.contracts.detection import FactBag
from packrelic.detection import DetectionScheduler
from packrelic.detection.scene.definitions import RECOMMENDED_SCENE_RULES_PAYLOAD
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


SCENE_PROTECT_CONFIG = with_detection_pipeline({
    "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
}, precheck=[
    {
        "name": "scene_protect",
        "enabled": True,
        "scene_rules": RECOMMENDED_SCENE_RULES_PAYLOAD,
    },
], scoring=[
    {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
    {"name": "embedded_payload_identity", "enabled": True},
])


def _evaluate(path: Path):
    bag = FactBag()
    bag.set("file.path", str(path))
    decision = DetectionScheduler(SCENE_PROTECT_CONFIG).evaluate_bag(bag)
    return decision, bag


def _write_rpg_maker(root: Path) -> Path:
    (root / "www" / "js").mkdir(parents=True)
    (root / "www" / "data").mkdir(parents=True)
    (root / "www" / "fonts").mkdir(parents=True)
    (root / "Game.exe").write_bytes(b"MZ")
    (root / "www" / "js" / "rpg_core.js").write_text("// core", encoding="utf-8")
    (root / "www" / "js" / "plugins.js").write_text("var $plugins = [];", encoding="utf-8")
    (root / "www" / "data" / "Map001.json").write_text("{}", encoding="utf-8")
    protected = root / "www" / "fonts" / "jfdotfont-20150527.7z"
    protected.write_bytes(b"7z\xbc\xaf\x27\x1c")
    return protected


def _write_renpy(root: Path) -> Path:
    (root / "game").mkdir(parents=True)
    (root / "renpy").mkdir()
    (root / "lib").mkdir()
    (root / "game" / "script.rpy").write_text("label start:\n    return\n", encoding="utf-8")
    (root / "game" / "options.rpy").write_text("define config.name = 'Synthetic'", encoding="utf-8")
    protected = root / "game" / "data.rpa"
    protected.write_bytes(b"RPA-3.0 synthetic")
    return protected


def _write_godot(root: Path) -> Path:
    (root / "packs").mkdir(parents=True)
    (root / "game.exe").write_bytes(b"MZ")
    (root / "project.godot").write_text("[application]\nconfig/name='Synthetic'", encoding="utf-8")
    protected = root / "data.pck"
    protected.write_bytes(b"GDPC synthetic")
    return protected


def _write_nwjs(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "nw.exe").write_bytes(b"MZ")
    protected = root / "package.nw"
    protected.write_bytes(make_zip({"package.json": "{\"main\":\"index.html\"}"}))
    return protected


def _write_nwjs_chromium_runtime(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "locales").mkdir()
    (root / "Game.exe").write_bytes(b"MZ")
    (root / "nw.pak").write_bytes(b"pak")
    (root / "icudtl.dat").write_bytes(b"icu")
    (root / "ffmpegsumo.dll").write_bytes(b"dll")
    protected = root / "package.nw"
    protected.write_bytes(make_zip({"package.json": "{\"main\":\"index.html\"}"}))
    return protected


def _write_electron(root: Path) -> Path:
    (root / "resources" / "app.asar.unpacked").mkdir(parents=True)
    (root / "app.exe").write_bytes(b"MZ")
    protected = root / "resources" / "app.asar"
    protected.write_bytes(b"asar synthetic")
    return protected


@pytest.mark.parametrize(
    ("scene_type", "builder"),
    [
        ("rpg_maker_game", _write_rpg_maker),
        ("renpy_game", _write_renpy),
        ("godot_game", _write_godot),
        ("nwjs_game", _write_nwjs),
        ("electron_app_game", _write_electron),
    ],
)
def test_runtime_layouts_protect_engine_resource_archives(tmp_path, scene_type, builder):
    protected = builder(tmp_path / scene_type)

    decision, bag = _evaluate(protected)

    assert decision.should_extract is False
    assert decision.stop_reason.startswith("Scene Protect")
    assert bag.get("scene.scene_type") == scene_type
    assert bag.get("scene.is_runtime_resource_archive") is True


def test_runtime_semantics_keep_generic_controls_extractable(tmp_path):
    generic_zip = tmp_path / "generic_controls" / "generic.zip"
    generic_zip.parent.mkdir(parents=True)
    generic_zip.write_bytes(make_zip({"payload.txt": "hello"}))

    disguised = tmp_path / "generic_controls" / "fakepicture.jpg"
    disguised.write_bytes(b"\xff\xd8synthetic image\xff\xd9" + b"7z\xbc\xaf\x27\x1c")

    zip_decision, zip_bag = _evaluate(generic_zip)
    disguised_decision, disguised_bag = _evaluate(disguised)

    assert zip_decision.should_extract is True
    assert zip_bag.get("scene.scene_type") == "generic"
    assert disguised_decision.should_extract is True
    assert disguised_bag.get("scene.scene_type") == "generic"
    assert disguised_bag.get("file.embedded_archive_found") is True


def test_chromium_nwjs_runtime_layout_is_recognized(tmp_path):
    protected = _write_nwjs_chromium_runtime(tmp_path / "chromium_nwjs")

    decision, bag = _evaluate(protected)

    assert decision.should_extract is False
    assert decision.stop_reason.startswith("Scene Protect")
    assert bag.get("scene.scene_type") == "nwjs_game"
    assert bag.get("scene.match_strength") == "strong"
    assert bag.get("scene.is_runtime_resource_archive") is True
