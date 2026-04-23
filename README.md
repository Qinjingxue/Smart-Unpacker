# Smart Unpacker

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

配置分为 `extraction_rules`、`post_extract`、`recursive_extract` 和 `performance` 四块。每个配置项的可选参数、默认值、含义、风险和常见示例请看：

[Smart Unpacker 配置文件详解](./docs/configuration.zh.md)

注意：`smart_unpacker_config.json` 必须保持合法 JSON，不能写注释；修改检测规则会直接影响误判/漏判风险，建议先用 `inspect --verbose` 或 `scan` 查看结果。`post_extract.archive_cleanup_mode` 设置为 `delete` 时会直接删除原压缩文件，不经过回收站，请谨慎使用。

## 命令概览

CLI 支持 `inspect`、`scan`、`extract`、`passwords` 和 `config` 子命令。各命令参数、临时配置覆盖、配置文件修改命令、JSON 输出结构和常见工作流请看：

[Smart Unpacker CLI 使用说明](./docs/cli.zh.md)

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
