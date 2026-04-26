# Smart Unpacker

Smart Unpacker 是一个面向 Windows 的智能批量解压CLI工具。它会先扫描文件和目录，结合扩展名、文件头、嵌入式压缩包证据、分卷关系、目录场景和 7-Zip 确认结果，尽量只解压真正应该解压的归档文件，使用codex开发。

主要功能是一键批量解压处理复杂的压缩包文件，该项目可以轻松处理各种压缩包脏数据，包括嵌套压缩，伪装carrier压缩包，分卷压缩，自解压，也能应对损坏，缺失分卷的压缩包。推荐注册为windows右键菜单使用

当前项目的 CLI 已支持中文，默认配置文件是 `smart_unpacker_config.json`。源码运行入口是 `python sunpack_cli.py`；Windows 打包后入口是 `sunpack.exe`。

## 主要能力

- 批量扫描目录和文件，自动生成解压任务。
- 识别常见压缩包、分卷压缩包和部分伪装/嵌入式压缩包。
- 对游戏、程序目录中的资源包进行保护，降低误解压风险。
- 支持密码列表、交互输入密码和内置高频密码表。
- 支持递归解压、单目录扁平化、成功后保留/回收站/删除原压缩包。
- 支持目录扫描黑名单、目录剪枝、最小检测大小和仅扫描当前目录模式。
- 递归解压会按输出目录内容和强场景目录保护策略决定是否继续扫描。
- 提供 `scan`、`inspect`、`config validate` 等诊断命令。
- 提供 Windows 右键菜单注册脚本，便于对文件夹直接执行解压。

## 环境准备

建议使用 Windows 和 Python 3.10 或更新版本。开发环境需要这些工具：

- Python 3.10+
- Rust toolchain，提供 `cargo`
- Visual Studio Build Tools 2022 或等价 C++17 编译器
- CMake 3.25+
- PowerShell 5+

Python 运行依赖在 `requirements.txt`，构建依赖在 `requirements-build.txt`。构建脚本会安装 PyInstaller、maturin 和 CMake，但不会安装 Rust 或 Visual Studio C++ 编译器。

推荐在 Windows 下直接执行开发环境脚本：

```powershell
.\scripts\setup_windows_dev.ps1
```

脚本会创建 `.venv`、安装运行依赖和 pytest、准备 `tools\7z.exe` / `tools\7z.dll` 等 7-Zip 文件，用 `maturin` 构建/安装 Rust 原生扩展，并用 CMake 构建 `7z.dll` C++ wrapper 到 `tools\sevenzip_password_tester_capi.dll`。需要同时准备 PyInstaller 等构建依赖时：

```powershell
.\scripts\setup_windows_dev.ps1 -IncludeBuildDeps
```

手动准备时可以按下面的步骤执行：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -r requirements-build.txt pytest
python -m maturin build --manifest-path native\smart_unpacker_native\Cargo.toml --release --out build\native-wheels-dev
$wheel = Get-ChildItem build\native-wheels-dev\smart_unpacker_native-*.whl | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1 -ExpandProperty FullName
python -m pip install --force-reinstall $wheel
cmake -S native\sevenzip_password_tester -B native\sevenzip_password_tester\build
cmake --build native\sevenzip_password_tester\build --config Release
ctest --test-dir native\sevenzip_password_tester\build -C Release --output-on-failure
Copy-Item native\sevenzip_password_tester\build\Release\sevenzip_password_tester_capi.dll tools\sevenzip_password_tester_capi.dll -Force
```

Windows 下最终解压要求存在 `tools\7z.exe` 或程序目录旁边的 `7z.exe`，不会回退到系统 PATH。检测、测试和密码尝试要求存在 `tools\sevenzip_password_tester_capi.dll` 和 `tools\7z.dll`，缺失时直接报错。

确认原生扩展可用：

```powershell
python -c "import smart_unpacker_native as n; print(n.native_available(), n.scanner_version())"
python -c "from smart_unpacker.extraction.internal.native_password_tester import NativePasswordTester; print(NativePasswordTester().available())"
```

## 快速使用

查看帮助：

```powershell
python sunpack_cli.py --help
```

扫描目录但不解压：

```powershell
python sunpack_cli.py scan D:\Downloads
```

查看详细判定过程：

```powershell
python sunpack_cli.py inspect D:\Downloads -v
```

执行解压：

```powershell
python sunpack_cli.py extract D:\Downloads
```

带密码解压：

```powershell
python sunpack_cli.py extract D:\Archives -p 123456 --pw-file .\passwords.txt
```

输出 JSON：

```powershell
python sunpack_cli.py scan D:\Downloads --json
```

打包后的程序使用同一套命令：

```powershell
.\dist\sunpack\sunpack.exe inspect D:\Downloads --json
```

## 常用命令

| 命令              | 说明                           |
| ----------------- | ------------------------------ |
| `extract`         | 执行预检查、扫描、解压和清理。 |
| `scan`            | 只生成可解压任务，不修改文件。 |
| `inspect`         | 输出每个文件的检测详情。       |
| `passwords`       | 查看会参与尝试的密码列表。     |
| `config show`     | 打印当前配置。                 |
| `config validate` | 校验配置和规则插件声明。       |

详细参数见 [CLI 参数说明](docs/cli_parameters.md)。

## 配置

主配置文件是 `smart_unpacker_config.json`。修改后建议执行：

```powershell
python sunpack_cli.py config validate
```

常调配置：

- `cli.language`：CLI 语言，中文可设为 `zh`。
- `thresholds`：压缩包判定阈值；中间可疑区间会自动进入确认层。
- `recursive_extract`：递归解压模式。
- `post_extract.archive_cleanup_mode`：成功后 `keep`、`recycle` 或 `delete`。
- `post_extract.flatten_single_directory`：是否扁平化单一顶层目录。
- `filesystem.directory_scan_mode`：目录扫描是否递归进入已有子目录。
- `filesystem.scan_filters`：目录扫描阶段的黑名单、剪枝目录、阻止扩展名和最小检测大小。
- `performance.scheduler_profile`：`auto`、`conservative` 或 `aggressive`。
- `detection.rule_pipeline`：检测规则流水线。

完整说明见 [配置文件说明](docs/configuration.md)。

## 规则插件

扫描和检测由 filesystem scan filters、Fact 采集器、处理器和三层规则组成：

- `filesystem.directory_scan_mode`：控制扫描目标目录时是否递归进入已有子目录。
- `filesystem.scan_filters`：在目录扫描阶段过滤黑名单路径、过小文件等明显不需要进入检测的条目。
- `precheck`：场景保护、高置信快速放行等需要检测事实的预检规则。
- `scoring`：扩展名、真实内容身份、场景扣分等打分规则。
- `confirmation`：7-Zip 探测和测试规则。

插件接口见 [规则插件说明](docs/rule_plugins.md)。

## 开发文档

开发环境、构建脚本和依赖说明见 [开发环境和构建说明](docs/development_setup.md)。模块边界、依赖方向和重构约束见 [开发边界说明](docs/development_boundaries.md)。

## 原生组件

项目包含两个原生组件：

- `native\smart_unpacker_native`：Rust/PyO3 扩展，用于目录扫描、magic 搜索、载体尾部/前缀扫描、ZIP central directory 文件名采样、轻量格式结构解析、PE overlay 解析，以及关系分组中目录文件枚举等热点。
- `native\sevenzip_password_tester`：C++/CMake wrapper，用于通过 `7z.dll` 执行 `7z l`/`7z t` 等价探测、测试和密码尝试。它会在开发和发行构建时复制为 `tools\sevenzip_password_tester_capi.dll`。

Python 层仍负责配置、规则判断、任务调度、分卷语义和最终解压。最终解压仍调用 `7z.exe x`。

## Windows 右键菜单

开发环境或发行目录下都可以注册当前用户的目录右键菜单：

```powershell
.\scripts\register_context_menu.ps1
```

脚本会优先使用 `sunpack.exe`，找不到时回退到 `python sunpack_cli.py`。默认菜单项会执行：

```powershell
sunpack extract <目标目录> --ask-pw --pause
```

取消注册：

```powershell
.\scripts\unregister_context_menu.ps1
```

## 测试

该项目为保证功能延续性，有较为完善的测试系统

运行单元和功能测试：

```powershell
pytest
```

运行项目自带冒烟/验收脚本：

```powershell
.\run_acceptance_tests.ps1
```

## 构建

Windows 打包脚本：

```powershell
.\scripts\build_windows.ps1
```

构建脚本会创建独立的 `.venv-build`，安装运行和构建依赖，使用 `maturin` 构建 `smart_unpacker_native` wheel，使用 CMake 构建 `sevenzip_password_tester_capi.dll`，再用 PyInstaller 打包 `sunpack.exe`。打包后脚本会检查 Rust `.pyd`、`7z.exe`、`7z.dll` 和 C++ wrapper DLL 已进入发行目录，并运行基础 smoke test。

常用参数：

```powershell
.\scripts\build_windows.ps1 -SkipTests
.\scripts\build_windows.ps1 -Clean
.\scripts\build_windows.ps1 -Version 1.2.3
```

构建产物会使用外部 `smart_unpacker_config.json`，方便用户在不重新打包的情况下调整规则和行为。发行包输出到 `release\sunpack-windows-x64-<version>.zip`。
