# SunPack

SunPack主要功能是批量处理大量混乱压缩包，可以实现右键菜单一键解压目录内所有压缩包，或者递归解压嵌套目录。还可以使用右键菜单监控文件夹，之后所有进入该文件夹内的混乱压缩包均会被自动解压，有密码只需复制密码，项目会读剪贴板自动记录并尝试。
主要交互模式是右键菜单调用和CLI命令行交互，

注意，该项目由于输入复杂，不保证稳定，目前项目仍在稳定性测试中

项目还有一个实验性深度学习的压缩包修复系统，但目前因为过于复杂而开发搁置。

## 命令速览

| 命令        | 说明                                                      |
| ----------- | --------------------------------------------------------- |
| `extract`   | 扫描、解压、验证、修复循环、后处理。 |
| `watch`     | 监控目录，发现稳定归档后自动解压                          |
| `scan`      | 只生成候选任务，不修改文件。                              |
| `inspect`   | 输出 detection diagnostics、analysis preview 和规则判定细节。 |
| `passwords` | 查看本次会参与尝试的密码列表。                            |

详细参数见 [CLI 参数说明](docs/cli_parameters.md)。

## 配置

主配置文件是 `sunpack_config.json`，另有高级配置`sunpack_advanced_config.json`

主配置文件优先覆盖高级配置相同字段配置，高级配置可手动将字段移至主配置

配置校验命令：

```powershell
python sunpack.py config validate
```

完整配置说明见 [配置文件说明](docs/configuration.md)。

## 开发相关

准备开发环境：

```powershell
.\scripts\setup_windows_dev.ps1
```

构建项目：

```powershell
.\scripts\build_windows.ps1
```

开发环境和构建说明见 [文档](docs/development_setup.md)。
开发边界见文档 [文档](docs\development_boundaries.md)

## 架构速览

```text
app/config
  -> coordinator
     filesystem->relations-> detection -> extraction -> verification
                             ^                            |
                             |                            v
                            +---------- repair -----------+
                          repair_inspection ──> analysis
     -> postprocess
```

## 测试

安装测试依赖并运行默认测试：

```powershell
python -m pip install -e ".[test]"
python -m pytest
```

验收测试：

```powershell
.\run_acceptance_tests.ps1
```
