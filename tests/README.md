# 测试结构

测试套件按“测试形态”组织，而不是按源码包组织。新增测试时，优先选择能锁住行为的最小测试，并通过项目公开入口表达预期行为。

## 目录说明

- `cases/`：数据驱动 JSON 用例。普通 CLI、检测、后处理和归档扫描场景优先放这里。
- `runners/`：`cases/` 的通用 pytest runner。一般不需要频繁修改。
- `helpers/`：共享构造器、断言、测试配置、归档 fixture 和 CLI 辅助工具。
- `unit/`：聚焦公开模块或契约的测试，不覆盖黑箱模块内部算法。
- `functional/`：跨模块行为测试，尽量避免真实外部解压。
- `integration/`：pipeline、解压和真实执行路径测试。
- `cli/`：CLI parser、命令契约和命令行为测试。
- `performance/`：轻量压力和并发行为测试。
- `performance_split_archives/`：分卷归档压力脚本，偏手动或专项验证，不属于默认 pytest 主路径。

## 数据驱动用例

如果一个场景能用 arrange/act/assert 数据描述，优先新增 JSON case，而不是新增 Python 测试文件。

当前用例类型：

- `cases/cli/*.json`：通过 `tests.helpers.cli_runner` 运行 `sunpack_cli.py`，检查 JSON 或文本命令契约。
- `cases/detection/*.json`：构造文件和 facts，评估单个 detection 目标，检查 decision 和 fact 输出。
- `cases/postprocess/*.json`：在临时工作区测试 cleanup、flatten 和 failed-log 动作。
- `cases/archive_scan/*/case.json`：复制 `files/` 目录，用 `DetectionScheduler` 扫描，并检查每个文件是否应判定为归档。完整 manifest 格式见 `tests/cases/archive_scan/README.md`。

共享断言路径使用点号写法，并支持包含点号的字典 key，例如 `facts.file.detected_ext`。

## 运行测试

运行默认 pytest 套件：

```powershell
pytest
```

只运行数据驱动用例：

```powershell
pytest tests/runners -q
```

运行项目验收脚本：

```powershell
.\run_acceptance_tests.ps1 -NoWait
```

运行本地 CI 风格检查：

```powershell
.\scripts\run_ci_tests.ps1
```

`run_acceptance_tests.ps1` 会分步运行 unit、functional、integration、CLI、runner 和 CLI smoke checks。`scripts/run_ci_tests.ps1` 会运行完整 pytest 套件，再执行两个 CLI smoke checks。

## 大文件性能压测

10 个 300MB 普通 zip 归档的真实解压并发压测挂在 pytest 性能测试体系下，默认跳过。需要时显式开启：

```powershell
pytest tests/performance/test_large_archives.py --run-large-archive-performance -s
```

默认会在 pytest 临时目录中生成 10 个约 300MB 的普通 `.zip` 文件，走 `PipelineRunner` 实际解压，并采样当前进程树中的 `7z.exe` 数量，确认调度器确实拉起多个 7z 进程并行工作。可按需调整规模和阈值：

```powershell
pytest tests/performance/test_large_archives.py --run-large-archive-performance -s --large-archive-count 10 --large-archive-size-mb 300 --large-archive-max-extract-seconds 300 --large-archive-min-parallel-7z 2 --large-archive-scheduler-profile auto
```

## 慢速真实归档测试

`tests/integration/test_real_archive_edge_cases.py` 默认保留一组快速真实归档 smoke 测试。完整格式矩阵标记为 `slow_real_archive`，默认跳过；需要时显式开启：

```powershell
pytest tests/integration/test_real_archive_edge_cases.py --run-slow-real-archives
```

## 公共接口边界

测试默认不直接导入 `*/internal/*`、`detection.pipeline.*`，也不调用下划线私有方法或 monkeypatch 私有实现。黑箱模块只通过公开入口测试行为，例如 `DetectionScheduler`、`ExtractionScheduler`、`PostProcessActions`、`DirectoryScanner`、`RelationsScheduler`、`RenameScheduler`、CLI 和 coordinator 编排入口。

确实需要覆盖新规则或检测场景时，优先使用 `cases/detection/`、`cases/archive_scan/` 或 functional 测试，并从 `DetectionScheduler` 进入，而不是直接测试 rule、processor、collector 的内部方法。

## 新增测试建议

场景能匹配现有 runner 时，新增 JSON case。只有需要新 runner、新 helper、新 fixture 或确实存在新的交互方式时，再新增 Python 测试。

常用位置：

- 新增 CLI 输出或命令形状：优先 `cases/cli/`；如果 parser 或命令公共契约需要直接覆盖，再加到 `cli/`。
- 新增规则行为：优先用 `cases/detection/` 从公开调度入口评估；如果文件系统扫描和候选构建也重要，用 `cases/archive_scan/`。
- 新增清理或扁平化行为：`cases/postprocess/`。
- 新增共享测试配置：`tests/helpers/config_factory.py`。
- 新增可复用文件系统构造：`tests/helpers/fs_builder.py` 或 `tests/helpers/generated_fixtures.py`。

昂贵的真实归档测试应放在 integration，或挂在慢速 marker 后面，保持默认测试套件足够快。
