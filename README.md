# Smart Unpacker

[中文](./README.md) | [English](./README.en.md) | [日本語](./README.ja.md)

Smart Unpacker 是一个面向 Windows 的 Python 命令行解压工具，使用AI开发
它主要用于批量处理伪装压缩包、嵌套压缩包、分卷压缩包、带密码压缩包、自解压文件，并尽量用统一流程完成检测、校验、解压和清理。
可注册为windows右键菜单，菜单会显示在文件夹或者目录背景下，右键调用，填入多个密码，自动尝试密码并解压，解压后直接把原来的压缩包移动到回收站，并自动压平单子目录。

# 使用方法

推荐使用windows的右键菜单调用程序。
下载release下的预构建压缩包，或者自行根据说明下载源码构建，也可直接源码运行。
下载release文件后解压压缩包到一个固定位置，运行 scripts/register_context_menu.ps1 可注册右键菜单，运行unregister_context_menu.ps1可取消右键菜单。
builtin_passwords.txt内为程序的内置密码，如果你不想每次解压都输入密码，可以把一堆常用密码都输入到这里，每次不输入密码就可以直接解压。

## 配置文件说明

smart_unpacker_config.json 是配置文件
min_inspection_size_bytes表示最小压缩包大小，比这个还小的文件程序不会识别处理，根据情况修改，调大可以减少大量杂乱小文件的性能影响，调小可以识别到小的伪装压缩包，默认1MB。
basic 下面是普通用户常用配置。
scheduler_profile表示并发策略，auto一般就可以了；设置成aggressive为激进策略，可能提升性能；设置成conservative为保守策略，如果发现程序运行时进程过多影响其他任务时可以设置。
advanced.scheduler 下面的配置都是并发的详细控制，默认全0，表示被scheduler_profile的配置覆盖，一旦填写具体数值会覆盖掉scheduler_profile的策略。

## 功能概览

- `inspect`：递归检查文件或目录，输出每个文件的识别结果、命中原因和是否建议解压。
- `scan`：按任务维度汇总可处理归档，便于先看扫描结果再决定是否执行解压。
- `extract`：执行扫描、密码尝试、归档校验、解压和后处理，并根据系统负载动态调整并发。
- `passwords`：查看当前最终会参与尝试的密码列表，包括命令行输入和内置高频密码。
- Windows 集成：可通过 PowerShell 脚本注册资源管理器右键菜单。
- Windows 构建：构建脚本会自动补齐缺失的 7-Zip 运行组件并生成可分发目录和 zip 包。

## 本地运行

1. 安装 Python 3。
2. 初始化本地开发环境：

```powershell
.\scripts\setup_windows_dev.ps1
```

这个脚本会：

- 创建 `.venv`
- 安装 `requirements.txt` 里的运行依赖
- 自动补齐 `tools` 目录里缺失的 7-Zip 组件

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

### 依赖

- 运行依赖：`requirements.txt`
- 构建依赖：`requirements-build.txt`
- 7-Zip 运行组件：构建脚本和本地初始化脚本会在缺失时自动下载并补齐

### 构建

```powershell
.\scripts\build_windows.ps1
```

构建过程自动执行测试，保证项目修改后不会误删普通文件

可选参数：

- `-SkipTests`：跳过测试，仅验证打包链路。
- `-Clean`：额外清理构建虚拟环境后重建。
- `-Version <string>`：覆盖默认版本号，用于发布命名。

构建完成后会生成：

- `dist/SmartUnpacker/`：可直接运行的发布目录
- `release/*.zip`：便于分发的压缩包

### 说明

本软件虽然经过复杂场景测试，但不保证一定不会误删文件，使用者请自负责任，开发者不承担文件损失责任
