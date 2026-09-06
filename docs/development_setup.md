# 开发环境和构建说明

SunPack 只维护一套公开源码、一套依赖声明和一条 Windows 构建链路。Python 依赖统一声明在根目录 `pyproject.toml`，不再使用多个 requirements 文件或私有构建脚本。

## 环境要求

- Windows 10/11
- PowerShell 5.1 或更新版本
- Python 3.10 或更新版本，架构必须与目标发行包一致
- `uv` 0.12 或更新版本
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
native/toast_host/        主程序内加载的 Windows toast DLL
tools/                    x64 外部工具和原生构建产物
tools-arm64/              ARM64 外部工具和原生构建产物
```

## Python 依赖

可安装的 extra：

| Extra | 用途 |
| --- | --- |
| 默认 | SunPack 运行依赖，不包含模型运行时 |
| `model-runtime` | x64 模型运行时依赖，包含 PyTorch 2.10 CPU、PyG 和 zstandard |
| `test` | pytest 与 zstandard 测试数据生成依赖 |
| `build` | Nuitka、maturin、CMake |
| `training` | 训练工具的附加依赖 |
| `dev` | build、test、training 的并集，不包含 `model-runtime` |

常用安装方式：

```powershell
uv sync --locked
uv sync --locked --extra test
uv sync --locked --extra dev
uv sync --locked --extra model-runtime
```

ARM64 的模型运行时由脚本使用 PyTorch CPU wheel 源单独安装；不要直接依赖 `model-runtime` extra 解析 ARM64 PyTorch。

开发环境由 `uv` 管理并锁定在 `uv.lock`，环境目录仍为 `.venv`。如果检测到旧 `.venv` 曾启用全局 site-packages，脚本会自动删除并重建，避免本机全局包影响依赖解析。

## 一键准备开发环境

```powershell
.\scripts\setup_windows_dev.ps1
```

脚本会：

1. 用 `uv sync --locked` 创建或复用隔离的 `.venv`
2. 从 `uv.lock` 安装统一的 `dev` extra（开发、测试和构建依赖）
3. 仅在 full 模式安装模型运行时依赖
4. 清理所有旧 `sunpack_native` 残留，构建并只安装最新 wheel
5. 准备对应架构的 `7z.exe`、`7z.dll` 和 license
6. 构建 `sunpack_sevenzip.dll`、`sunpack_sevenzip_worker.exe` 和 `sunpack_toast.dll`
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
uv sync --locked --extra build
.\.venv\Scripts\maturin.exe build --manifest-path native\sunpack_native\Cargo.toml --release --target-dir .cache\rust-target\x64 --out build\native-wheels-dev
$wheel = Get-ChildItem build\native-wheels-dev\sunpack_native-*.whl |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1 -ExpandProperty FullName
uv pip uninstall --python .\.venv\Scripts\python.exe sunpack-native
uv pip install --python .\.venv\Scripts\python.exe --reinstall $wheel
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

### Windows toast

```powershell
cmake -S native\toast_host -B native\toast_host\build-x64 -A x64
cmake --build native\toast_host\build-x64 --config Release
ctest --test-dir native\toast_host\build-x64 -C Release --output-on-failure
Copy-Item native\toast_host\build-x64\Release\sunpack_toast.dll tools\sunpack_toast.dll -Force
```

只有持续运行的 watch 创建 `ToastManager`。它在主程序内的专用线程上加载 DLL、维护 WinRT apartment 和 COM 按钮回调，并处理进度限频与完成通知 TTL；停止或重载 watch 时等待该线程释放资源。普通 CLI 请求和独立的 `watch start --once` 不创建通知管理器。watch 与 CLI 共用引擎时，通知仍仅来自 watch 调度器。

发行包只携带 `tools\sunpack_toast.dll`，无需通知辅助进程。通知身份在 watch 首次创建通知管理器时按需注册，卸载时由 `sunpack-runtime.exe --unregister-toast` 清理；Windows 的冷激活也进入主程序的 `--toast-activated` 入口，不启动解压引擎或 watch。安装器不会创建开始菜单入口。

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

直接 pytest 会跳过需要 NTFS Watch Broker 的用例。完整验收通过 `run_acceptance_tests.ps1` 在同一个 PowerShell 流程中准备依赖和一次临时测试服务，然后直接调用 pytest；所有测试结束后由自动提权 PowerShell 卸载服务，不会触碰本机已安装的发布服务：

```powershell
.\run_acceptance_tests.ps1 -NoWait
```

CI 环境不会弹 UAC；验收服务管理器未提权时会立即失败，避免等待交互进程而卡住。

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
.\scripts\build_windows.ps1 -Clean
.\scripts\build_windows.ps1 -SkipTests
.\scripts\build_windows.ps1 -Version 1.2.3
```

Windows 发布只生成安装器，不再生成 portable ZIP。构建环境必须安装 Inno Setup 6；
缺少 `ISCC.exe` 时会在耗时构建开始前失败，也可以通过 `-InnoCompilerPath` 指定编译器路径。

构建过程：

1. 创建或复用统一的 `.venv`（`-Clean` 时清理重建）
2. 安装项目 `dev` extra
3. 构建并安装 Rust wheel
4. 构建和测试 C++ bridge/worker
5. 可选运行 acceptance tests
6. Nuitka 构建一个无控制台的 standalone runtime；原生 `sunpack.exe` 提供 CLI 控制台交互，watch 通过私有进程模式参数启动同一 runtime 的独立进程。
7. 复制配置、密码表、工具和 license；full 构建额外复制整个 `models/`，lite 构建显式排除并校验 torch/PyG 运行时
8. 校验关键 PE 文件架构
9. 运行 packaged CLI、bridge smoke checks；full 构建额外运行模型加载 smoke check
10. 用 Inno Setup 创建 Windows 安装器

输出：

```text
dist\sunpack-<arch>-<repair_system>\
release\sunpack-windows-<arch>-<repair_system>-<version>-setup.exe
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
