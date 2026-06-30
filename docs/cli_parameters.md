# CLI 参数说明

入口脚本：

```powershell
python sunpack.py <command> [options] [paths...]
```

打包后的 Windows 程序通常可直接使用：

```powershell
sunpack.exe <command> [options] [paths...]
```

顶层命令：

- `extract`：预检查、扫描、解压、后处理和清理。
- `watch`：监控目录，文件稳定后自动进入 extract pipeline。
- `scan`：只扫描可解压任务，不修改文件。
- `inspect`：输出每个文件的检测细节，不修改文件。
- `passwords`：查看实际会参与尝试的密码列表。
- `config`：查看或校验简化配置与高级配置合并后的有效配置。

## 通用输出参数

这些参数用于 `extract`、`scan`、`inspect`：

| 参数 | 说明 |
| --- | --- |
| `-j`, `--json` | 以 JSON 格式输出结果，适合脚本调用。 |
| `-q`, `--quiet` | 减少终端输出。 |
| `-v`, `--verbose` | 输出更多调试和检测细节。 |
| `--pause` | 命令结束后等待按键退出，适合双击或右键菜单。 |
| `--no-pause` | 命令结束后不暂停。 |

`passwords` 只支持 `--json`，不支持 `--quiet`、`--verbose`、`--pause`。`config` 支持 `--json` 和 `--quiet`。

所有命令的 `--json` 输出都遵循同一外层形状：`command`、`inputs`、`summary`、`errors`、`items`、`tasks`、`logs`。不同命令会根据语义填充 `items` 或 `tasks`。

## extract

用法：

```powershell
python sunpack.py extract [options] <paths...>
```

`paths` 可以是一个或多个文件、目录。目录会被扫描并生成解压任务。

参数：

| 参数 | 说明 |
| --- | --- |
| `-p PASSWORD`, `--password PASSWORD` | 手动提供一个解压密码，可重复传入多次。 |
| `--pw-file PASSWORD_FILE` | 从文本文件读取密码，每行一个。 |
| `--ask-pw` | 在终端交互输入密码，空行结束。 |
| `--no-builtin-pw` | 禁用内置高频密码表。 |
| `--recur VALUE` | 覆盖递归解压设置。当前解析器接受正整数、`*`、`?`。 |
| `--sched {auto,conservative,aggressive}` | 覆盖并发调度档位。 |
| `--cleanup VALUE` | 覆盖成功解压后的原压缩包处理方式：`d` 删除，`r` 回收站，`k` 不动。 |
| `--direct-file` | 把每个输入路径当作归档文件，跳过初始目录扫描和 detection，直接进入 analysis -> extraction -> verification/repair -> postprocess。只适合明确指定文件。 |
| `--flatten` | 解压后扁平化单一顶层目录。 |
| `--no-flatten` | 保留解压目录结构。 |

`--recur` 的取值：

- `1`、`2`、`3` 等正整数：固定递归轮数。
- `*`：无限递归，内部上限为 999 轮。
- `?`：提示模式，内部上限为 999 轮。

示例：

```powershell
python sunpack.py extract D:\Downloads
python sunpack.py extract D:\A.7z -p 123456 -p secret
python sunpack.py extract D:\Archives --pw-file .\passwords.txt --cleanup r --sched auto
python sunpack.py extract D:\Nested --recur * --no-flatten
python sunpack.py extract --direct-file D:\MaybeArchive.bin
```

退出码：

- `0`：所有任务均完整成功。
- `1`：至少一个解压任务失败。
- `2`：参数、路径或配置错误。
- `3`：运行时异常。
- `4`：没有失败任务，但至少一个任务仅部分成功。

## scan

用法：

```powershell
python sunpack.py scan [options] <paths...>
```

`scan` 会扫描输入路径，输出识别到的解压任务、分卷关系、检测扩展名、分数和命中规则。它不会解压，也不会清理文件。

目录扫描范围受 `filesystem.directory_scan_mode`、`filesystem.scan_filters_enabled` 和 `filesystem.scan_filters` 影响；被黑名单、目录剪枝、阻止扩展名、大小范围或修改时间范围过滤掉的文件不会进入 detection。

示例：

```powershell
python sunpack.py scan D:\Downloads
python sunpack.py scan D:\Downloads --json
python sunpack.py scan D:\Downloads -v
```

## inspect

用法：

```powershell
python sunpack.py inspect [options] <paths...>
```

`inspect` 面向诊断：它会列出候选文件的判定结果、分数、决策阶段、停止原因、确认层结果和 fact 错误。

使用 `-v` 时，文本输出会额外打印生效配置、命中规则、打分明细、确认层结果和 fact 错误；JSON 输出会保留这些结构化字段，便于对误判做回归用例。

额外参数：

| 参数 | 说明 |
| --- | --- |
| `--archives-only` | 只显示最终判定为可解压的项目。 |

示例：

```powershell
python sunpack.py inspect D:\Downloads
python sunpack.py inspect D:\Downloads --archives-only
python sunpack.py inspect D:\Downloads --json
python sunpack.py inspect D:\Downloads -v
```

## watch

用法：

```powershell
python sunpack.py watch [options] <paths...>
```

`watch` 会监听一个或多个文件夹。文件发生变化后进入活跃态，持续静默达到配置阈值时触发一次 `extract` pipeline；相同快照不因解压结果而重试。新分卷和密码源变化会开启新的活跃周期。

常用参数与 `extract` 基本一致，包括密码、输出目录、递归、调度档位、清理策略、JSON/quiet/verbose/pause 等。

示例：

```powershell
python sunpack.py watch D:\Downloads --out-dir D:\Unpacked
python sunpack.py watch D:\Incoming -p 123456 --cleanup r --recur *
```

## passwords

用法：

```powershell
python sunpack.py passwords [options]
```

参数：

| 参数 | 说明 |
| --- | --- |
| `-j`, `--json` | 以 JSON 输出密码来源汇总。 |
| `-p PASSWORD`, `--password PASSWORD` | 手动提供密码，可重复传入。 |
| `--pw-file PASSWORD_FILE` | 从文本文件读取密码，每行一个。 |
| `--ask-pw` | 在终端交互输入密码。 |
| `--no-builtin-pw` | 不使用内置高频密码表。 |

密码合并顺序为：最近成功密码、同目录密码、命令行密码、剪贴板密码、内置密码。重复项会去重。

`passwords` 命令展示本次命令参数、配置开启时启动时读取的当前剪贴板文本，以及内置密码合并后的列表；最近成功密码是在一次 `extract` 运行过程中由 `passwords` 层维护的运行态列表。

示例：

```powershell
python sunpack.py passwords
python sunpack.py passwords -p 123456 --no-builtin-pw
python sunpack.py passwords --pw-file .\passwords.txt --json
```

## config

用法：

```powershell
python sunpack.py config [options] <show|validate>
```

子命令：

| 子命令 | 说明 |
| --- | --- |
| `show` | 打印当前读取到的配置文件内容。 |
| `validate` | 校验 JSON、规则名、规则配置 schema 和 fact schema。 |

参数：

| 参数 | 说明 |
| --- | --- |
| `-j`, `--json` | 以 JSON 输出结果。 |
| `-q`, `--quiet` | 减少普通文本输出。 |

示例：

```powershell
python sunpack.py config show
python sunpack.py config validate
python sunpack.py config validate --json
```


## Windows 右键菜单

项目提供当前用户级右键菜单脚本：

```powershell
.\scripts\register_context_menu.ps1
.\scripts\unregister_context_menu.ps1
```

发行包内的注册脚本会使用脚本父目录中的 `sunpack.exe`，因此不依赖 `sunpack-x64-lite` 等外层目录名。从源码树运行时，脚本也会识别唯一的 `dist/sunpack-*/sunpack.exe`；若存在多个构建产物，必须用 `-AppPath` 明确选择。找不到打包程序时才使用 `python sunpack.py`。卸载脚本只删除固定注册表键，不依赖安装目录。默认菜单项对文件夹或目录空白处执行 `extract <目标> --ask-pw --pause`，适合给非终端使用场景保留暂停窗口。
