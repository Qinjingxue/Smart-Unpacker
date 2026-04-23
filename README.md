# Smart Unpacker

[中文](./README.md) | [English](./README.en.md) | [日本語](./README.ja.md)

Smart Unpacker 是一个面向 Windows 的 Python 命令行解压工具，使用 AI 辅助开发。

它适合批量处理伪装压缩包、嵌套压缩包、分卷压缩包、带密码压缩包和自解压文件，尽量用一套统一流程完成检测、校验、解压和清理。

推荐注册为 Windows 右键菜单使用。注册后可以在文件夹或目录空白处右键启动，输入多个密码后自动尝试解压；成功处理后，程序会把原压缩包移动到回收站，并自动压平只有单个子目录的解压结果。

## 适用场景

- 批量解压文件夹中的多种压缩包。
- 识别扩展名被伪装或缺失的压缩包。
- 处理分卷压缩包、嵌套压缩包、自解压文件。
- 自动尝试命令行密码、密码文件和内置高频密码。
- 解压完成后清理原压缩包，并整理单层目录结构。

## 快速使用

推荐使用 Release 中的预构建压缩包。

1. 下载 Release 压缩包并解压到一个固定目录。
2. 运行右键菜单注册脚本：

```powershell
.\scripts\register_context_menu.ps1
```

3. 在资源管理器中右键文件夹或目录空白处，选择 `Smart Unpacker`。
4. 如需取消右键菜单，运行：

```powershell
.\scripts\unregister_context_menu.ps1
```

`builtin_passwords.txt` 是内置密码列表。如果你不想每次手动输入常用密码，可以把这些密码按行写入该文件，程序会在解压时自动参与尝试。

## 配置

主配置文件是 `smart_unpacker_config.json`。

常用配置：

- `basic.min_inspection_size_bytes`：最小检查文件大小。小于该值的文件不会被识别和处理。默认值为 `1048576`，即 `1 MB`。调大可以减少大量小文件带来的性能开销，调小可以识别更小的伪装压缩包。
- `basic.scheduler_profile`：并发策略。通常保持 `auto` 即可；`aggressive` 更偏性能；`conservative` 更保守，适合程序进程过多或影响其他任务时使用。
- `advanced.scheduler`：并发细节控制。默认值均为 `0`，表示跟随 `scheduler_profile`。填写具体数值后，会覆盖对应的 profile 行为。

## 命令概览

- `inspect`：递归检查文件或目录，输出每个文件的识别结果、命中原因和是否建议解压。
- `scan`：按任务维度汇总可处理归档，方便先查看扫描结果再决定是否解压。
- `extract`：执行扫描、密码尝试、归档校验、解压和后处理，并根据系统负载动态调整并发。
- `passwords`：查看最终会参与尝试的密码列表，包括命令行输入、密码文件和内置高频密码。

通用参数：

- `--json`：以 JSON 格式输出结果。
- `--quiet`：减少终端输出。
- `--verbose`：输出更详细的信息。
- `--pause-on-exit`：命令结束后等待按键退出，适合右键菜单场景。

密码参数：

- `-p, --password`：指定解压密码，可重复传入多次。
- `--password-file`：指定密码文件，按每行一个密码读取。
- `--prompt-passwords`：通过终端交互输入密码列表。
- `--no-builtin-passwords`：禁用内置高频密码。

## 本地运行

1. 安装 Python 3。
2. 初始化本地开发环境：

```powershell
.\scripts\setup_windows_dev.ps1
```

该脚本会：

- 创建 `.venv`。
- 安装 `requirements.txt` 中的运行依赖。
- 自动补齐 `tools` 目录中缺失的 7-Zip 运行组件。

3. 运行 CLI：

```powershell
python smart-unpacker.py <command> [options] [paths...]
```

示例：

```powershell
python smart-unpacker.py inspect .\fixtures
python smart-unpacker.py scan .\archives
python smart-unpacker.py extract -p "secret" .\archives\sample.zip
python smart-unpacker.py extract --prompt-passwords .\archives
python smart-unpacker.py passwords
```

## 测试

完整逻辑验收测试：

```powershell
.\run_acceptance_tests.ps1
```

GitHub Actions 使用的 CI 测试入口：

```powershell
.\scripts\run_ci_tests.ps1
```

测试相关的本地路径和工具查找规则统一放在：

```text
tests/test_config.json
```

当前合成样本覆盖的目录语义家族包括 RPG Maker、Ren'Py、Godot、NW.js 和 Electron。

完整测试中的 RAR 样本需要 `Rar.exe`。如果本机缺失，依赖 RAR 的样本生成部分会自动跳过；`Rar.exe` 路径可在 `tests/test_config.json` 中配置。

## 依赖与构建

依赖文件：

- 运行依赖：`requirements.txt`
- 构建依赖：`requirements-build.txt`
- 7-Zip 运行组件：本地初始化脚本和构建脚本会在缺失时自动下载补齐。

构建 Windows 发布包：

```powershell
.\scripts\build_windows.ps1
```

构建过程会自动执行测试，尽量避免项目修改后误删普通文件。

可选参数：

- `-SkipTests`：跳过测试，仅验证打包链路。
- `-Clean`：额外清理构建虚拟环境后重建。
- `-Version <string>`：覆盖默认版本号，用于发布命名。

构建完成后会生成：

- `dist/SmartUnpacker/`：可直接运行的发布目录。
- `release/*.zip`：便于分发的压缩包。

## 风险说明

本软件虽然经过复杂场景测试，但不保证一定不会误删文件。请在确认数据可恢复或已有备份的前提下使用；由使用造成的文件损失需由使用者自行承担。

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
