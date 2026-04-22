# Smart Unpacker

Smart Unpacker 是一个 Python 命令行工具。
主要功能就是处理复杂的压缩包各种伪装和解密，能在输入密码列表后一键解压目录或者文件夹下各种奇奇怪怪的伪装压缩包。

## 功能概览

- `inspect` / `scan`：分析文件或目录，判断是否为可提取归档、是否加密、是否属于分卷集合。
- `extract`：执行扫描、校验、解压和后处理，并根据系统负载动态调整并发。
- `passwords`：查看当前实际会参与尝试的密码列表。
- Windows 集成：可通过 PowerShell 脚本把工具注册到资源管理器右键菜单。

## 项目结构

- `smart-unpacker.py`：仓库根目录入口脚本。
- `smart_unpacker/app/`：CLI 参数解析与命令分发。
- `smart_unpacker/core/`：扫描、解压、清理、调度等核心逻辑。
- `smart_unpacker/detection/`：归档检测、分卷识别、场景规则。
- `smart_unpacker/support/`：日志、资源定位、密码读取等通用支持代码。
- `scripts/`：Windows 右键菜单脚本、构建脚本、基准工具。
- `tools/`：随项目分发的 7-Zip 可执行文件及其依赖。
- `tests/`：单元测试与验收测试。

## 本地运行

1. 安装 Python 3。
2. 安装运行依赖：

```powershell
pip install -r requirements.txt
```

3. 运行 CLI：

```powershell
python smart-unpacker.py <command> [options] <paths...>
```

示例：

```powershell
python smart-unpacker.py inspect .\fixtures
python smart-unpacker.py extract -p "secret" .\archives\sample.zip
python smart-unpacker.py extract --prompt-passwords .\archives
```

## 测试

完整逻辑验收测试：

```powershell
.\run_acceptance_tests.ps1
```

## Windows 构建与发布

当前 Windows 发布方式为“绿色版目录 + zip 包”。构建完成后，主程序位于：

```text
dist/SmartUnpacker/SmartUnpacker.exe
```

发布目录中会同时包含以下运行时资源：

- `tools/*`
- `builtin_passwords.txt`
- `smart_unpacker_config.json`
- `licenses/7zip-license.txt`
- `scripts/register_context_menu.ps1`
- `scripts/unregister_context_menu.ps1`

### 构建依赖

- 运行依赖：`requirements.txt`
- 构建依赖：`requirements-build.txt`

### 一键构建

```powershell
.\scripts\build_windows.ps1
```

可选参数：

- `-SkipTests`：跳过测试，仅验证打包链路。
- `-Clean`：额外清理构建虚拟环境后重建。
- `-Version <string>`：覆盖默认版本号，用于发布命名。

### 构建脚本会做什么

1. 检查当前环境是否为 Windows，并确认 Python、`tools/7z.exe`、`SmartUnpacker.spec` 等输入存在。
2. 创建或复用 `.venv-build` 虚拟环境。
3. 安装运行依赖和构建依赖。
4. 清理旧的 `build/`、`dist/`、`release/` 目录。
5. 运行 `.\run_acceptance_tests.ps1` 作为质量门禁。
6. 调用 `pyinstaller SmartUnpacker.spec` 生成目录版 exe。
7. 复制外置运行资源、7-Zip 许可证和右键菜单脚本到发布目录，并生成 `VERSION.txt` 构建元数据。
8. 执行发布后冒烟测试。
9. 生成 `release/SmartUnpacker-windows-x64-<version>.zip`。

### 发布产物

默认发布目录结构如下：

```text
dist/
  SmartUnpacker/
    SmartUnpacker.exe
    builtin_passwords.txt
    smart_unpacker_config.json
    VERSION.txt
    licenses/
    tools/
    scripts/
```

压缩包输出位置：

```text
release/SmartUnpacker-windows-x64-<version>.zip
```

### 可直接修改的发布包文件

以下文件设计为可在发布包中直接调整：

- `smart_unpacker_config.json`
- `builtin_passwords.txt`

## 第三方依赖与分发说明

当前发布包默认附带未修改的 7-Zip 命令行工具及其相关 DLL，用于统一提供归档检测、校验和解压能力。

- 随包分发的第三方组件位于 `tools/`
- 7-Zip 许可证文件位于 `licenses/7zip-license.txt`
- 当前构建流程只在发布包中保留一份外置 `tools/`，不会再额外复制一份到 `_internal`
- 如需替换 7-Zip 版本，建议同时更新 `tools/` 目录内容和 `licenses/7zip-license.txt`

本项目不会修改 7-Zip 二进制文件，也不会宣称获得 7-Zip 官方背书。对外分发时，应保留随包的许可证说明文件。

## Windows 右键菜单

注册脚本支持两种启动方式：

- 优先使用打包后的 `SmartUnpacker.exe`
- 如果未找到 exe，则回退为 `python smart-unpacker.py`

注册：

```powershell
.\scripts\register_context_menu.ps1
```

注销：

```powershell
.\scripts\unregister_context_menu.ps1
```
