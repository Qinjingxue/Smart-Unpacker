from pathlib import Path

from PyInstaller.building.build_main import Analysis, COLLECT, EXE, PYZ
from PyInstaller.utils.hooks import collect_submodules


project_root = Path(SPECPATH)

hiddenimports = ["smart_unpacker_native"]
for package in (
    "watchdog",
    "zstandard",
    "smart_unpacker.app.commands",
    "smart_unpacker.config.fields",
    "smart_unpacker.filesystem.filters.modules",
    "smart_unpacker.detection.pipeline.facts.collectors",
    "smart_unpacker.detection.pipeline.processors.modules",
    "smart_unpacker.detection.pipeline.rules.hard_stop",
    "smart_unpacker.detection.pipeline.rules.precheck",
    "smart_unpacker.detection.pipeline.rules.scoring",
    "smart_unpacker.detection.pipeline.rules.confirmation",
    "smart_unpacker.analysis.pipeline.modules",
    "smart_unpacker.repair.pipeline.modules",
    "smart_unpacker.verification.methods",
):
    hiddenimports.extend(collect_submodules(package))

a = Analysis(
    ["sunpack_cli.py"],
    pathex=[str(project_root)],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="sunpack",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    name="sunpack",
)
