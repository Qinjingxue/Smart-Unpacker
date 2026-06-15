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
```

## Python 依赖

可安装的 extra：

| Extra | 用途 |
| --- | --- |
| 默认 | SunPack 运行依赖、PyTorch 和 PyG 模型运行时 |
| `test` | pytest |
| `build` | PyInstaller、maturin、CMake |
| `training` | 训练工具的附加依赖 |
| `dev` | build、test、training 的并集 |

常用安装方式：

```powershell
python -m pip install -e .
python -m pip install -e ".[test]"
python -m pip install -e ".[dev]"
```

## 一键准备开发环境

```powershell
.\scripts\setup_windows_dev.ps1
```

脚本会：

1. 创建或复用 `.venv`
2. 从 `pyproject.toml` 安装 `test` extra
3. 构建并安装 `sunpack_native`
4. 准备对应架构的 `7z.exe`、`7z.dll` 和 license
5. 构建 `sunpack_sevenzip.dll` 和 `sunpack_sevenzip_worker.exe`
6. 把 C++ 产物复制到工具目录
7. 运行 Python、Rust、C++ 和 CLI smoke checks

包含发行构建依赖：

```powershell
.\scripts\setup_windows_dev.ps1 -IncludeBuildDeps
```

清理后重建：

```powershell
.\scripts\setup_windows_dev.ps1 -Clean -IncludeBuildDeps
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
python -m maturin build --manifest-path native\sunpack_native\Cargo.toml --release --out build\native-wheels-dev
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
.\.venv\Scripts\python.exe sunpack.py models status --load
```

三个命令分别验证 Rust 扩展、C++ bridge 和正式模型资产。

## 模型资产

正式模型位于 `models/`，入口是 `models/manifest.json`。manifest 中每个模型包含：

- `model_type`
- `semantics`
- `algorithm`
- `packaged_path`
- `sha256`

`sha256` 是对应目录中 `model.pt` 的哈希。训练结果不会自动成为运行时模型；发布新模型时必须把完整资产复制到 `models/<format>/<role>`，更新 manifest，并运行：

```powershell
python sunpack.py models status --load --json
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
.\scripts\build_windows.ps1 -Clean
.\scripts\build_windows.ps1 -SkipTests
.\scripts\build_windows.ps1 -Version 1.2.3
```

构建过程：

1. 创建或清理 `.venv-build`
2. 安装项目 `build` extra
3. 构建并安装 Rust wheel
4. 构建和测试 C++ bridge/worker
5. 可选运行 acceptance tests
6. 用 `SunPack.spec` 生成 PyInstaller onedir 包
7. 复制配置、密码表、工具、license 和整个 `models/`
8. 校验关键 PE 文件架构
9. 运行 packaged CLI、bridge 和模型加载 smoke checks
10. 用随附 7-Zip 创建并测试发布 ZIP

输出：

```text
dist\sunpack\
release\sunpack-windows-<arch>-<version>.zip
```

ARM64 必须在 ARM64 Windows 和 ARM64 Python 环境中构建。已有目录可独立校验：

```powershell
.\scripts\verify_windows_package_arch.ps1 -PackageRoot dist\sunpack -Arch x64
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
