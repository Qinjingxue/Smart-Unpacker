# 开发环境和构建说明

SunPack 只维护一套公开源码、一套依赖声明和一条 Windows 构建链路。Python 依赖统一声明在根目录 `pyproject.toml`，不再使用多个 requirements 文件或私有构建脚本。

## 环境要求

- Windows 10/11
- PowerShell 5.1 或更新版本
- Python 3.10 或更新版本，架构必须与目标发行包一致
- Rust MSVC toolchain，提供 `cargo`
- Visual Studio Build Tools 2022，包含 C++17 编译器
- 网络连接，用于首次安装 Python 依赖和准备 7-Zip 文件

项目使用的主要目录：

```text
sunpack/                  产品运行时代码
sunpack/repair/model/     正式修复模型运行时
sunpack/repair/search/    修复搜索图与提案
repair_training/          数据、训练与评估工具
models/                   正式发布模型资产
native/sunpack_native/    Rust/PyO3 扩展
native/sevenzip_bridge/   Windows 7z.dll bridge 与 worker
tools/                    x64 外部工具和原生构建产物
tools-arm64/              ARM64 外部工具和原生构建产物
```

## Python 依赖

可安装的 extra：

| Extra | 用途 |
| --- | --- |
| 默认 | SunPack 运行依赖，不包含模型运行时 |
| `model-runtime` | x64 模型运行时依赖，包含 PyTorch 2.7 CPU 和 PyG |
| `test` | pytest |
| `build` | PyInstaller、Nuitka、maturin、CMake |
| `training` | 训练工具的附加依赖 |
| `dev` | build、test、training 的并集，不包含 `model-runtime` |

常用安装方式：

```powershell
python -m pip install -e .
python -m pip install -e ".[test]"
python -m pip install -e ".[dev]"
python -m pip install -e ".[model-runtime]"
```

ARM64 的模型运行时由脚本使用 PyTorch CPU wheel 源单独安装；不要直接依赖 `model-runtime` extra 解析 ARM64 PyTorch。

开发环境脚本创建普通 venv，不启用 `--system-site-packages`。如果检测到旧 `.venv` 曾启用全局 site-packages，脚本会自动删除并重建，避免本机全局包影响依赖解析。

## 一键准备开发环境

```powershell
.\scripts\setup_windows_dev.ps1
```

脚本会：

1. 创建或复用隔离的 `.venv`
2. 从 `pyproject.toml` 安装统一的 `dev` extra（开发、测试和构建依赖）
3. 安装模型运行时依赖；full 和 lite 共用同一套完整环境
4. 构建并安装 `sunpack_native`
5. 准备对应架构的 `7z.exe`、`7z.dll` 和 license
6. 构建 `sunpack_sevenzip.dll` 和 `sunpack_sevenzip_worker.exe`
7. 把 C++ 产物复制到工具目录
8. 运行 Python、Rust、C++ 和 CLI smoke checks

使用完整环境验证 lite 模式（环境中的 torch/PyG 不会被打进 lite 包）：

```powershell
.\scripts\setup_windows_dev.ps1 -RepairSystem lite
```

清理后重建：

```powershell
.\scripts\setup_windows_dev.ps1 -Clean
```

ARM64 开发环境：

```powershell
.\scripts\setup_windows_dev.ps1 -Arch arm64
```

目标架构必须与当前 Python 进程架构一致。

## 手动构建原生组件

### Rust/PyO3

```powershell
python -m pip install -e ".[build]"
python -m maturin build --manifest-path native\sunpack_native\Cargo.toml --release --target-dir .cache\rust-target\x64 --out build\native-wheels-dev
$wheel = Get-ChildItem build\native-wheels-dev\sunpack_native-*.whl |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1 -ExpandProperty FullName
python -m pip install --force-reinstall $wheel
```

### C++ 7-Zip bridge

```powershell
cmake -S native\sevenzip_bridge -B native\sevenzip_bridge\build-x64 -A x64
cmake --build native\sevenzip_bridge\build-x64 --config Release
ctest --test-dir native\sevenzip_bridge\build-x64 -C Release --output-on-failure
Copy-Item native\sevenzip_bridge\build-x64\Release\sunpack_sevenzip.dll tools\sunpack_sevenzip.dll -Force
Copy-Item native\sevenzip_bridge\build-x64\Release\sunpack_sevenzip_worker.exe tools\sunpack_sevenzip_worker.exe -Force
```

bridge 运行时还需要同一工具目录中的 `7z.dll`。

## Smoke Checks

```powershell
.\.venv\Scripts\python.exe -c "import sunpack_native as n; print(n.native_available(), n.scanner_version())"
.\.venv\Scripts\python.exe -c "from sunpack.support.sevenzip_bridge import NativePasswordTester; print(NativePasswordTester().available())"
.\.venv\Scripts\python.exe -m pytest tests\unit\test_model_runtime.py
```

三个命令分别验证 Rust 扩展、C++ bridge 和正式模型资产。`-RepairSystem lite` 环境下，模型运行时测试会验证“修复系统未包含”的正常状态，不会尝试加载模型。

## 模型资产

正式模型位于 `models/`，入口是 `models/manifest.json`。manifest 中每个模型包含：

- `model_type`
- `semantics`
- `algorithm`
- `packaged_path`
- `sha256`

`sha256` 是对应目录中 `model.pt` 的哈希。训练结果不会自动成为运行时模型；发布新模型时必须把完整资产复制到 `models/<format>/<role>`，更新 manifest，并运行：

```powershell
python -m pytest tests\unit\test_model_runtime.py
```

产品代码只能从 `sunpack.repair.model` 加载模型，不能从 `repair_training/runs` 或外部包加载。

## 测试

完整 pytest：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

项目 CI 风格测试：

```powershell
.\scripts\run_ci_tests.ps1
```

完整验收：

```powershell
.\run_acceptance_tests.ps1 -NoWait
```

慢速真实归档和大文件性能测试需要显式开关，详见 `tests/README.md`。

## Windows 发行构建

唯一正式构建入口：

```powershell
.\scripts\build_windows.ps1
```

常用参数：

```powershell
.\scripts\build_windows.ps1 -Arch x64
.\scripts\build_windows.ps1 -Arch x64 -RepairSystem full
.\scripts\build_windows.ps1 -Arch x64 -RepairSystem lite
.\scripts\build_windows.ps1 -Packager nuitka
.\scripts\build_windows.ps1 -Packager pyinstaller
.\scripts\build_windows.ps1 -Clean
.\scripts\build_windows.ps1 -SkipTests
.\scripts\build_windows.ps1 -Version 1.2.3
.\scripts\build_windows.ps1 -RequireInstaller
```

如果本机没有安装 Inno Setup 6，普通本地构建会给出警告并继续生成 portable ZIP；
正式发行或需要安装器时使用 `-RequireInstaller`，缺少 `ISCC.exe` 将在耗时构建开始前失败。

构建过程：

1. 创建或复用统一的 `.venv`（`-Clean` 时清理重建）
2. 安装项目 `dev` extra
3. 构建并安装 Rust wheel
4. 构建和测试 C++ bridge/worker
5. 可选运行 acceptance tests
6. 在交互终端选择 `[N]uitka` 或 `[P]yInstaller`；也可用 `-Packager nuitka|pyinstaller` 指定。非交互构建默认使用 PyInstaller。
7. PyInstaller 使用 `SunPack.spec` 生成 onedir 包；Nuitka 分别构建 console 和 GUI standalone 包后合并到同一发行目录。
8. 复制配置、密码表、工具和 license；full 构建额外复制整个 `models/`，lite 构建显式排除并校验 torch/PyG 运行时
9. 校验关键 PE 文件架构
10. 运行 packaged CLI、bridge smoke checks；full 构建额外运行模型加载 smoke check
11. 用随附 7-Zip 创建并测试发布 ZIP

输出：

```text
dist\sunpack-<arch>-<repair_system>\
release\sunpack-windows-<arch>-<repair_system>-<version>.zip
```

ARM64 必须在 ARM64 Windows 和 ARM64 Python 环境中构建。已有目录可独立校验：

```powershell
.\scripts\verify_windows_package_arch.ps1 -PackageRoot dist\sunpack-x64-lite -Arch x64
```

## 运行时原生文件

x64 开发环境默认使用：

```text
tools\7z.exe
tools\7z.dll
tools\sunpack_sevenzip.dll
tools\sunpack_sevenzip_worker.exe
```

`sunpack_sevenzip.dll` 提供 probe、test、密码尝试、健康检查、资源分析和 manifest C ABI。`sunpack_sevenzip_worker.exe` 读取 JSON job，通过 `7z.dll` 解压文件、分卷和虚拟输入。`7z.exe` 仅用于开发 fixture、手工诊断、文件来源和发布 ZIP 创建。
