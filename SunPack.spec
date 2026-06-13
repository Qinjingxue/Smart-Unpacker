import os
from pathlib import Path

from PyInstaller.building.build_main import Analysis, COLLECT, EXE, PYZ
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata


project_root = Path(SPECPATH)
icon_path = project_root / "sunpack.ico"
dist_name = os.environ.get("SUNPACK_DIST_NAME", "sunpack")
exe_name = os.environ.get("SUNPACK_EXE_NAME", "sunpack")

hiddenimports = ["sunpack_native", "sunpack_repair_models", "torch", "torch_geometric"]
datas = []
for package in (
    "watchdog",
    "zstandard",
    "sunpack.app.commands",
    "sunpack.config.fields",
    "sunpack.filesystem.filters.modules",
    "sunpack.detection.pipeline.facts.collectors",
    "sunpack.detection.pipeline.processors.modules",
    "sunpack.detection.pipeline.rules.hard_stop",
    "sunpack.detection.pipeline.rules.precheck",
    "sunpack.detection.pipeline.rules.scoring",
    "sunpack.detection.pipeline.rules.confirmation",
    "sunpack.analysis.structure_pipeline.modules",
    "sunpack.analysis.fuzzy_pipeline.modules",
    "sunpack.repair.pipeline.modules",
    "sunpack.repair.pipeline.modules.rar",
    "sunpack.repair.pipeline.modules.seven_zip",
    "sunpack.repair.pipeline.modules.zip",
    "sunpack.repair.pipeline.modules.tar",
    "sunpack.passwords.candidates",
    "sunpack.extraction.internal",
    "sunpack.rename.internal",
    "sunpack.relations.internal",
    "sunpack.postprocess.internal",
    "sunpack.verification.methods",
    "sunpack.model_runtime",
    "repair_training.core.diagnosis_graph",
    "repair_training.core.diagnosis_gnn",
    "repair_training.core.repair_policy_transformer",
    "repair_training.formats.zip",
):
    hiddenimports.extend(collect_submodules(package))

hiddenimports.extend(collect_submodules("torch_geometric"))
for distribution in ("torch", "torch-geometric"):
    datas.extend(copy_metadata(distribution))

a = Analysis(
    ["sunpack.py"],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
    module_collection_mode={"torch_geometric": "py"},
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=exe_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    icon=str(icon_path),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    name=dist_name,
)
