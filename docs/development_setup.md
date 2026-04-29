# 开发环境和构建说明

本文档说明从源码开发、运行测试和构建 Windows 发行包需要的依赖与脚本。

## 开发依赖

必需工具：

- Windows
- PowerShell 5 或更新版本
- Python 3.10 或更新版本
- Rust toolchain，提供 `cargo`
- Visual Studio Build Tools 2022 或等价 C++17 编译器
- CMake 3.25 或更新版本

Python 依赖：

- `requirements.txt`：运行依赖，目前包括 `psutil`、`send2trash`、`watchdog`、`zstandard`
- `requirements-build.txt`：构建依赖，目前包括 `pyinstaller`、`maturin`、`cmake`
- `pytest`：开发和测试依赖，由开发环境脚本安装

第三方二进制依赖：

- `tools\7z.exe`：开发 fixture、手工诊断和 7-Zip 文件来源
- `tools\7z.dll`：C++ wrapper 运行时使用
- `tools\sevenzip_password_tester_capi.dll`：项目本地构建的 7z.dll wrapper
- `tools\sevenzip_worker.exe`：项目解压后端 worker

`setup_windows_dev.ps1` 可以自动下载/准备 7-Zip 文件和 license，但不会安装 Rust 或 Visual Studio C++ 编译器。

## 一键准备开发环境

```powershell
.\scripts\setup_windows_dev.ps1
```

脚本会执行：

1. 创建 `.venv`
2. 安装运行依赖和 pytest
3. 安装/查找 `maturin`
4. 构建并安装 Rust/PyO3 扩展 `sunpack_native`
5. 准备 `tools\7z.exe`、`tools\7z.dll` 和 7-Zip license
6. 安装/查找 CMake
7. 构建 C++ wrapper `sevenzip_password_tester_capi.dll` 和 `sevenzip_worker.exe`
8. 将 wrapper DLL 和 worker 复制到 `tools\`
9. 运行 CLI 和 native smoke checks

需要同时安装 PyInstaller 等打包依赖：

```powershell
.\scripts\setup_windows_dev.ps1 -IncludeBuildDeps
```

清理并重建开发环境：

```powershell
.\scripts\setup_windows_dev.ps1 -Clean -IncludeBuildDeps
```

## 手动构建原生组件

Rust native：

```powershell
python -m pip install -r requirements-build.txt
python -m maturin build --manifest-path native\sunpack_native\Cargo.toml --release --out build\native-wheels-dev
$wheel = Get-ChildItem build\native-wheels-dev\sunpack_native-*.whl | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1 -ExpandProperty FullName
python -m pip install --force-reinstall $wheel
```

C++ 7z.dll wrapper：

```powershell
cmake -S native\sevenzip_password_tester -B native\sevenzip_password_tester\build
cmake --build native\sevenzip_password_tester\build --config Release
ctest --test-dir native\sevenzip_password_tester\build -C Release --output-on-failure
Copy-Item native\sevenzip_password_tester\build\Release\sevenzip_password_tester_capi.dll tools\sevenzip_password_tester_capi.dll -Force
Copy-Item native\sevenzip_password_tester\build\Release\sevenzip_worker.exe tools\sevenzip_worker.exe -Force
```

## Smoke Checks

```powershell
.\.venv\Scripts\python.exe -c "import sunpack_native as n; print(n.native_available(), n.scanner_version())"
.\.venv\Scripts\python.exe -c "from sunpack.support.sevenzip_native import NativePasswordTester; print(NativePasswordTester().available())"
```

第一个命令确认 Rust native 可导入。第二个命令确认 `tools\sevenzip_password_tester_capi.dll` 和 `tools\7z.dll` 都可被找到。

## 测试

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

本地 CI 风格检查：

```powershell
.\scripts\run_ci_tests.ps1
```

验收脚本：

```powershell
.\run_acceptance_tests.ps1
```

## Windows 发行构建

```powershell
.\scripts\build_windows.ps1
```

构建脚本会：

1. 创建 `.venv-build`
2. 安装运行和构建依赖
3. 构建/安装 `sunpack_native`
4. 构建 `sevenzip_password_tester_capi.dll` 并复制到 `tools\`
5. 可选运行验收测试
6. 使用 PyInstaller 构建 `sunpack.exe`
7. 将 `tools\7z.exe`、`tools\7z.dll`、`tools\sevenzip_password_tester_capi.dll`、`tools\sevenzip_worker.exe` 和 license 复制到发行目录
8. 运行 packaged smoke tests
9. 生成 `release\sunpack-windows-<arch>-<version>.zip`

常用参数：

```powershell
.\scripts\build_windows.ps1 -SkipTests
.\scripts\build_windows.ps1 -Clean
.\scripts\build_windows.ps1 -Version 1.2.3
```

架构参数：

```powershell
.\scripts\build_windows.ps1 -Arch x64
.\scripts\build_windows.ps1 -Arch arm64
```

`x64` 是默认值。Windows ARM64 最终可执行文件必须在 ARM64 Windows + ARM64 Python 环境中构建；脚本会拒绝在 x64 Python 下生成“伪 ARM64”包。构建过程会静态校验 `sunpack.exe`、`sunpack_native`、`7z.exe`、`7z.dll`、`sevenzip_password_tester_capi.dll` 和 `sevenzip_worker.exe` 的 PE machine 架构。

已有发行目录也可以独立做静态架构校验：

```powershell
.\scripts\verify_windows_package_arch.ps1 -PackageRoot dist\sunpack -Arch x64
.\scripts\verify_windows_package_arch.ps1 -PackageRoot dist\sunpack-arm64 -Arch arm64
```

## 原生组件职责

`sunpack_native` 负责跨平台热点：

- 目录扫描
- 单目录普通文件枚举
- magic 搜索
- carrier archive 扫描
- ZIP central directory 文件名采样
- 轻量格式结构解析
- PE overlay 解析
- analysis binary view、signature prepass 和 fuzzy binary profile
- repair 层二进制 I/O、range copy/concat/patch 写入
- ZIP/TAR/压缩流/7z/RAR 部分深度修复的 native 实现
- verification 输出目录 CRC/readability 扫描和 path/basename 索引匹配
- ZIP/RAR/7z/password fast verifier 热路径

`sevenzip_password_tester_capi.dll` 负责 Windows 7z.dll 热点：

- archive probe，替代检测路径中的 `7z l`
- archive test，替代检测路径中的 `7z t`
- 密码数组尝试，避免为每个密码启动 `7z.exe`
- archive state manifest，供 verification 比较归档条目和输出文件
- worker 解压，接收 JSON job，调用 7z.dll 处理普通文件、file range、concat range、native/staged volumes 和 patch-plan 虚拟输入

最终解压由 `sevenzip_worker.exe` 通过 `7z.dll` 执行。`7z.exe` 仍保留在工具目录中，主要用于开发 fixture、手工诊断和 7-Zip 文件来源。
