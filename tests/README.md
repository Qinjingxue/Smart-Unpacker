# 测试结构

测试套件按“测试形态”组织，而不是按源码包组织。新增测试时，优先选择能锁住行为的最小测试，并通过项目公开入口表达预期行为。

## 目录说明

- `helpers/`：共享构造器、断言、测试配置、归档 fixture 和 CLI 辅助工具。
- `unit/`：聚焦公开模块或契约的测试，不覆盖黑箱模块内部算法。
- `functional/`：跨模块行为测试，尽量避免真实外部解压。
- `integration/`：pipeline、解压和真实执行路径测试。
- `real/`：按计划组织的真实归档和真实 watch 端到端矩阵；这里是完整真实场景的权威入口。
- `cli/`：CLI parser、命令契约和命令行为测试。
- `training/`：训练产物与正式模型运行时之间的评估和一致性测试。

性能测量、profile 和压力脚本统一放在仓库根目录的 `benchmarks/`，不参与
pytest 收集。pytest 中只保留行为断言；资源或时序稳定性断言使用 opt-in marker。

## 运行测试

运行默认 pytest 套件：

```powershell
python -m pip install -e ".[test]"
python -m pytest
```

列出性能场景：

```powershell
python -m benchmarks --list
```

运行项目验收脚本：

```powershell
.\run_acceptance_tests.ps1 -NoWait
```

运行本地 CI 风格检查：

```powershell
.\scripts\run_ci_tests.ps1
```

`run_acceptance_tests.ps1` 只保留外部功能验收：CLI contract、`tests/real/test_real_archive_boundaries.py` 和 CLI smoke checks。压缩包修复、损坏归档恢复、真实归档边界、训练边界、模型张量化和模块契约测试留在 pytest/CI 专项路径中运行。`scripts/run_ci_tests.ps1` 会运行 unit、functional、CLI、混合分卷 acceptance 和 CLI smoke checks。

完整真实归档/watch 场景统一从 `tests/real/` 运行；`tests/integration/` 只保留真实场景中仍有独立价值的底层关系解析、原生桥接、错误分类、性能和密码源更新契约，避免同一行为在两套端到端矩阵中重复维护。

## 慢速真实归档测试

`tests/integration/test_real_archive_edge_cases.py` 默认保留一组快速真实归档 smoke 测试。完整格式矩阵标记为 `slow_real_archive`，默认跳过；需要时显式开启：

```powershell
pytest tests/integration/test_real_archive_edge_cases.py --run-slow-real-archives
```

真实归档计划的完整入口示例：

```powershell
pytest tests/real -q
```

## 公共接口边界

测试默认不直接导入 `*/internal/*`、`detection.pipeline.*`，也不调用下划线私有方法或 monkeypatch 私有实现。黑箱模块只通过公开入口测试行为，例如 `DetectionScheduler`、`ExtractionScheduler`、`PostProcessActions`、`DirectoryScanner`、`RelationsScheduler`、`RenameScheduler`、CLI 和 coordinator 编排入口。

确实需要覆盖新规则或检测场景时，优先使用 functional 或 integration 测试，并从 `DetectionScheduler` 等公开入口进入，而不是直接测试 rule、processor、collector 的内部方法。

## 新增测试建议

常用位置：

- 新增 CLI 输出或命令形状：放到 `cli/`。
- 新增规则行为：放到 `functional/`；如果文件系统扫描和候选构建也重要，放到 `integration/`。
- 新增清理或扁平化行为：放到 `unit/` 或 `functional/`。
- 新增共享测试配置：`tests/helpers/config_factory.py`。
- 新增可复用文件系统构造：`tests/helpers/fs_builder.py` 或 `tests/helpers/generated_fixtures.py`。

昂贵的真实归档测试应放在 integration，或挂在慢速 marker 后面，保持默认测试套件足够快。
