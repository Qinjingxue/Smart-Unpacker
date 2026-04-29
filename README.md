# PackRelic

PackRelic 是一个 Windows-first 的智能归档处理与损坏压缩包尽力恢复工具。它不只是批量调用 7-Zip 解压，而是围绕真实文件状态建立一条可循环的 pipeline：

```text
detection -> analysis -> extraction -> verification -> repair -> extraction -> verification
```

项目的目标是：在复杂下载目录、游戏/程序目录、伪装载体、分卷包、嵌套包和损坏包里，尽量找出真正应该处理的归档；解压失败时尽量恢复可用文件；恢复出多个候选时用 verification 比较完整度，保留更好的结果。

当前项目的 CLI 已支持中文，默认配置文件是 `packrelic_config.json`。源码入口是 `python pkrc.py`；Windows 打包后入口是 `pkrc.exe`。

## 核心能力

- **智能候选识别**：结合扩展名、magic bytes、ZIP/7z/RAR/TAR 结构事实、embedded payload、PE overlay、目录场景和 7z.dll probe/test 判断文件是否值得解压。
- **场景保护**：识别游戏、程序、资源目录，降低把 `.dll`、模型权重、Office 容器、资源包等误当普通压缩包处理的概率。
- **分卷与虚拟输入**：识别标准分卷、编号卷、RAR/7z 分卷和 SFX companion；analysis 可产出 `file_range`、`concat_ranges` 等虚拟输入供 worker 解压。
- **真实 worker 解压**：最终解压由 `sevenzip_worker.exe` 调用 `7z.dll` 完成，不走 `7z.exe x` 文本封装。
- **verification 驱动结果判断**：不只看 worker 成功/失败，而是检查输出目录、manifest、归档条目、CRC、样本可读性、文件完整度和部分恢复进度。
- **repair beam 循环**：修复模块生成 patch plan，候选会重新解压并进入 verification；比较算法按完整度、失败数、patch 成本、来源完整性等选择更优结果，没有提升时主动停止。
- **损坏包尽力恢复**：支持 ZIP central directory/local header 修复、entry quarantine、deep partial recovery、conflict resolver；TAR checksum/trailing/PAX/GNU longname/sparse 修复；gzip/bzip2/xz/zstd 截断和尾部垃圾处理；7z start/next header/边界/CRC/solid block salvage；RAR block/end/carrier/file quarantine 修复。
- **嵌套与载体恢复**：可从损坏外壳或 carrier 中扫描内层 ZIP/7z/RAR/TAR/gzip 等载荷，并把内层包送回 pipeline。
- **Native-first 热路径**：Rust 承接目录扫描、二进制视图、signature prepass、结构 probe、carrier scan、repair I/O、CRC/readability、候选匹配索引和密码 fast verifier；C++ 承接 7z.dll ABI 与 worker。
- **适合右键菜单和 watch**：提供 Windows 右键菜单脚本，也支持 `watch` 目录监控，文件稳定后自动处理。

## 当前定位

PackRelic 更像一个“归档恢复协调器”而不是普通解压器：

- 对干净压缩包：批量、递归、密码、分卷、清理和扁平化。
- 对可疑文件：通过 detection/analysis 尽量避免误判。
- 对损坏压缩包：先提取可用部分，再让 repair 生成候选，最后由 verification 比较产物质量。
- 对大批量任务：通过 scheduler profile、resource guard、analysis cache、worker 复用和 Rust 热路径控制性能。

## 快速开始

准备开发环境：

```powershell
.\scripts\setup_windows_dev.ps1
```

包含打包依赖：

```powershell
.\scripts\setup_windows_dev.ps1 -IncludeBuildDeps
```

确认 native 组件可用：

```powershell
python -c "import packrelic_native as n; print(n.native_available(), n.scanner_version())"
python -c "from packrelic.support.sevenzip_native import NativePasswordTester; print(NativePasswordTester().available())"
```

常用命令：

```powershell
python pkrc.py scan D:\Downloads
python pkrc.py inspect D:\Downloads -v
python pkrc.py extract D:\Downloads
python pkrc.py watch D:\Downloads --out-dir D:\Unpacked
python pkrc.py extract D:\Archives -p 123456 --pw-file .\passwords.txt
python pkrc.py config validate
```

打包后的程序使用同一套命令：

```powershell
.\dist\\packrelic\pkrc.exe extract D:\Downloads
```

## 命令速览

| 命令 | 说明 |
| --- | --- |
| `extract` | 扫描、analysis、解压、verification、repair 循环、后处理。 |
| `watch` | 监控目录，发现稳定归档后自动进入 extract pipeline。 |
| `scan` | 只生成候选任务，不修改文件。 |
| `inspect` | 输出检测、analysis 和规则判定细节。 |
| `passwords` | 查看本次会参与尝试的密码列表。 |
| `config show` | 打印当前配置。 |
| `config validate` | 校验 JSON、规则、verification method 和 fact schema。 |

详细参数见 [CLI 参数说明](docs/cli_parameters.md)。

## 配置重点

主配置文件是 `packrelic_config.json`。修改后建议执行：

```powershell
python pkrc.py config validate
```

常用配置：

- `filesystem.scan_filters`：目录剪枝、黑名单、最小检测大小。
- `detection.rule_pipeline`：候选识别、场景保护、结构打分和确认层。
- `analysis`：结构分析、signature prepass、fuzzy binary profile、批量 analysis cache。
- `verification`：输出存在性、manifest、归档 CRC、可读性抽样、部分恢复阈值。
- `repair`：repair stages、安全策略、deep 限制、auto deep、beam、模块开关和资源上限。
- `performance`：scheduler profile、worker 超时、profile calibration、resource guard。
- `recursive_extract`：递归解压策略，`*` 无限递归，正整数为轮数，`?` 每轮询问。
- `post_extract.archive_cleanup_mode`：成功后 `d` 删除、`r` 回收站、`k` 保留。

完整说明见 [配置文件说明](docs/configuration.md)。

## 架构速览

```text
app/config
  -> coordinator
     -> detection -> analysis -> extraction -> verification
                                      ^              |
                                      |              v
                                      +---- repair <-+
     -> postprocess
```

重要边界：

- `detection` 只判断候选是否应处理。
- `analysis` 只描述结构、边界、损坏标志和可用输入视图。
- `extraction` 只执行 worker 解压。
- `verification` 只评价结果质量和下一步建议。
- `repair` 只生成候选或 patch plan，不直接宣称成功。
- `coordinator` 负责循环、比较、资源限制、summary 和最终归档处理。

详细约束见 [开发边界说明](docs/development_boundaries.md)。

## 原生组件

项目是 Python + Rust + C++ 三层协作：

- `packrelic/`：配置、CLI、调度、规则、verification/repair 决策编排。
- `native/packrelic_native/`：Rust/PyO3 热路径，包括目录扫描、二进制结构分析、repair I/O、CRC/readability、candidate matching、deep repair native 实现等。
- `native/sevenzip_password_tester/`：C++/CMake 7z.dll wrapper，提供 probe/test、密码数组尝试和 `sevenzip_worker.exe`。

运行时必须有：

```text
tools\7z.exe
tools\7z.dll
tools\sevenzip_password_tester_capi.dll
tools\sevenzip_worker.exe
```

`7z.exe` 主要保留给开发 fixture、手工诊断和 7-Zip 文件来源；正式解压后端是 `sevenzip_worker.exe` + `7z.dll`。

## 开发与测试

运行默认测试：

```powershell
pytest
```

验收测试：

```powershell
.\run_acceptance_tests.ps1
```

本地 CI 风格检查：

```powershell
.\scripts\run_ci_tests.ps1
```

慢速真实归档/性能测试默认不跑，可显式打开：

```powershell
pytest --run-slow-real-archives
pytest --run-large-archive-performance -s
```

开发环境和构建说明见 [development_setup.md](docs/development_setup.md)。

## Windows 右键菜单

注册当前用户右键菜单：

```powershell
.\scripts\register_context_menu.ps1
```

默认菜单项会执行：

```powershell
pkrc extract <目标目录> --ask-pw --pause
```

取消注册：

```powershell
.\scripts\unregister_context_menu.ps1
```

## 构建

Windows 打包：

```powershell
.\scripts\build_windows.ps1
```

常用参数：

```powershell
.\scripts\build_windows.ps1 -SkipTests
.\scripts\build_windows.ps1 -Clean
.\scripts\build_windows.ps1 -Version 1.2.3
```

构建脚本会准备 `.venv-build`，构建 Rust wheel 和 C++ worker，用 PyInstaller 生成 `pkrc.exe`，复制 `packrelic_config.json`、`builtin_passwords.txt` 和 `tools/` 运行文件，并执行 packaged smoke test。发行包输出到 `release\packrelic-windows-x64-<version>.zip`。
