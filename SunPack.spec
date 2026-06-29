import os
from pathlib import Path

from PyInstaller.building.build_main import Analysis, COLLECT, EXE, PYZ
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata


project_root = Path(SPECPATH)
icon_path = project_root / "sunpack.ico"
dist_name = os.environ.get("SUNPACK_DIST_NAME", "sunpack")
exe_name = os.environ.get("SUNPACK_EXE_NAME", "sunpack")
watch_exe_name = os.environ.get("SUNPACK_WATCH_EXE_NAME", "sunpack-watch")
repair_system = os.environ.get("SUNPACK_REPAIR_SYSTEM", "full").strip().lower()
include_repair_models = repair_system != "lite"
runtime_hook_path = project_root / "build" / "sunpack_repair_system_runtime.py"
runtime_hook_path.parent.mkdir(parents=True, exist_ok=True)
runtime_hook_path.write_text(
    "import os\n"
    f"os.environ['SUNPACK_REPAIR_SYSTEM'] = {repair_system!r}\n",
    encoding="utf-8",
)

hiddenimports = ["sunpack_native"]
datas = []
for package in (
    "watchdog",
    "zstandard",
    "sunpack.cli.commands",
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
    "sunpack.repair.search",
):
    hiddenimports.extend(collect_submodules(package))

if include_repair_models:
    hiddenimports.extend(["torch", "torch_geometric"])
    for package in (
        "sunpack.repair.model",
        "sunpack.repair.model.diagnosis",
        "sunpack.repair.model.policy",
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
    runtime_hooks=[str(runtime_hook_path)],
    excludes=[] if include_repair_models else ["torch", "torch_geometric"],
    noarchive=False,
    optimize=0,
    module_collection_mode={"torch_geometric": "py"} if include_repair_models else {},
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

watch_exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=watch_exe_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=True,
    icon=str(icon_path),
)

coll = COLLECT(
    exe,
    watch_exe,
    a.binaries,
    a.datas,
    name=dist_name,
)
