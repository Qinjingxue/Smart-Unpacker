from pathlib import Path

from PyInstaller.building.build_main import Analysis, COLLECT, EXE, PYZ
from PyInstaller.utils.hooks import collect_submodules


project_root = Path(SPECPATH)

hiddenimports = ["packrelic_native"]
for package in (
    "watchdog",
    "zstandard",
    "packrelic.app.commands",
    "packrelic.config.fields",
    "packrelic.filesystem.filters.modules",
    "packrelic.detection.pipeline.facts.collectors",
    "packrelic.detection.pipeline.processors.modules",
    "packrelic.detection.pipeline.rules.hard_stop",
    "packrelic.detection.pipeline.rules.precheck",
    "packrelic.detection.pipeline.rules.scoring",
    "packrelic.detection.pipeline.rules.confirmation",
    "packrelic.analysis.structure_pipeline.modules",
    "packrelic.analysis.fuzzy_pipeline.modules",
    "packrelic.repair.pipeline.modules",
    "packrelic.repair.pipeline.modules.rar",
    "packrelic.repair.pipeline.modules.seven_zip",
    "packrelic.repair.pipeline.modules.zip",
    "packrelic.repair.pipeline.modules.tar",
    "packrelic.passwords.candidates",
    "packrelic.extraction.internal",
    "packrelic.rename.internal",
    "packrelic.relations.internal",
    "packrelic.postprocess.internal",
    "packrelic.verification.methods",
):
    hiddenimports.extend(collect_submodules(package))

a = Analysis(
    ["pkrc.py"],
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
    name="pkrc",
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
    name="packrelic",
)
