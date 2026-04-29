# 开发边界说明

本文档是 SunPack 当前架构的边界约定。项目已经进入 native-first、verification-driven repair loop 和模块流水线阶段：文件系统扫描/监控、关系、检测、结构分析、密码、解压、校验、修复、后处理和 CLI 都应保持清晰职责。

## 总原则

1. 跨领域调用公开入口，不直接依赖别的领域的 `internal`。
2. `contracts` 放共享数据契约，不放流程控制。
3. `coordinator` 只编排流程，不实现领域算法。
4. `app` 只做 CLI 参数、交互和输出适配。
5. `support` 只放跨领域基础设施和外部 ABI 绑定，不放业务策略。
6. Rust/C++ 原生层承接性能热点和 ABI 适配，不拥有最终业务 decision。
7. 配置别名属于用户接口，可以保留；内部兼容壳、Python 逻辑 fallback 和旧接口桥应避免堆积。

## 推荐依赖方向

```text
app
  -> config
  -> coordinator
  -> passwords
  -> filesystem.watcher

coordinator
  -> detection
  -> analysis
  -> extraction
  -> verification
  -> repair
  -> postprocess
  -> rename
  -> contracts

detection
  -> contracts
  -> filesystem
  -> relations public API
  -> support/native helpers

analysis
  -> native binary view/probes
  -> contracts/result objects

extraction
  -> contracts
  -> passwords
  -> relations public API
  -> rename public API
  -> sevenzip worker

repair
  -> native binary I/O
  -> analysis evidence
  -> repair modules

verification
  -> contracts
  -> extraction result
  -> passwords session

postprocess
  -> contracts.RunContext
  -> postprocess internal actions

filesystem / relations / rename
  -> contracts
  -> sunpack_native narrow helpers

passwords
  -> support.sevenzip_native
  -> native/Rust fast verifiers

config
  -> support

contracts
  -> standard library
```

## 公开入口

| 领域 | 公开入口 | 职责 |
| ---- | -------- | ---- |
| CLI | `sunpack.app.cli.main` | 命令行入口。 |
| 配置 | `config.loader.load_config` / `config.schema` | 配置读取、校验、归一化。 |
| 契约 | `contracts.*` | 跨模块共享数据结构，包括 `RunContext`。 |
| 文件系统 | `filesystem.directory_scanner.DirectoryScanner` | 目录扫描和过滤。 |
| 关系 | `relations.RelationsScheduler` | 分卷、候选组、逻辑名和分卷成员查询。 |
| 检测 | `detection.DetectionScheduler` / `ArchiveTaskProvider` | 候选 facts、规则判断、任务生成。 |
| 递归策略 | `detection.NestedOutputScanPolicy` | 判断输出目录是否进入下一轮扫描。 |
| 结构分析 | `analysis.ArchiveAnalysisScheduler` | 对已确认候选做结构分析和边界标注。 |
| 密码 | `sunpack.passwords` | 密码候选、调度、fast verifier、7z.dll 最终确认。 |
| 解压 | `extraction.scheduler.ExtractionScheduler` | 单归档输出目录、密码解析、worker 解压。 |
| 校验 | `verification.VerificationScheduler` | 解压结果完整度、来源完整性和下一步决策。 |
| 修复 | `repair.RepairScheduler` | 根据 verification repair 决策生成修复候选。 |
| 后处理 | `postprocess.actions.PostProcessActions` | 成功后清理和扁平化。 |
| 文件系统监控 | `filesystem.watcher.WatchScheduler` | watchdog 事件、稳定文件队列和自动处理。 |
| Native ABI | `support.sevenzip_native` | C++ 7z.dll wrapper 绑定和缓存。 |

## 领域边界

### app

`app` 只负责 CLI 适配：参数解析、密码交互、配置覆盖、结果输出和退出码。它可以调用 coordinator、filesystem.watcher、passwords 和 config 的公开入口，不直接导入 detection/extraction/repair 的内部实现。

### config

`config` 接管外部配置读取、字段声明、归一化和展示。配置别名如 `recursive_extract: "*" / "?"`、`filesystem.directory_scan_mode: "*" / "-"`、`archive_cleanup_mode: "d/r/k"` 是用户接口的一部分，可以保留。领域运行时应消费归一化后的内部值。

### contracts

`contracts` 是共享数据契约层。`FactBag`、`ArchiveTask`、`ExtractionResult` 相关跨模块数据和 `RunContext` 应放这里。不要跨模块读取私有字段，例如 `FactBag._facts`。

### filesystem

`filesystem` 负责目录遍历、过滤、`DirectorySnapshot` 构建，以及 watchdog 监控能力。watcher 复用 `filesystem.scan_filters`，稳定文件直接交给调用方注入的主流程 runner；它不按扩展名自行判断归档。

### relations

`relations` 负责文件之间的关系：分卷主文件、成员、SFX companion、模糊分卷候选和逻辑名。外部模块只能调用 `RelationsScheduler`，不要直接依赖 `relations.internal`。

允许公开的关系能力包括：

- `build_candidate_groups(snapshot)`
- `detect_split_role(filename)`
- `logical_name_for_archive(filename)`
- `select_first_volume(paths)`
- `should_scan_split_siblings(...)`
- `find_standard_split_siblings(archive)`
- `parse_numbered_volume(path)`

### detection

`detection` 只回答“候选是否应进入解压任务”。它分三层：

- `facts`：采集初等事实，例如路径、大小、magic bytes、scene marker。
- `processors`：从初等 facts 推导高等 facts，例如结构事实、embedded payload、scene context、7z probe/test。
- `rules`：只读 facts 和配置，输出 accept/reject/score/confirm。

规则层不应依赖 processor 实现细节；共享默认值放到公共 constants/config 模块。

### analysis

`analysis` 是压缩包结构分析层。输入应是 detection 已筛出的候选或 relation 分卷组；输出格式证据、片段边界、置信度和损坏标记。分析层使用 Rust `AnalysisBinaryView`、signature prepass 和格式 probe；不保留 Python 文件读取/结构解析 fallback。

### passwords

`passwords` 管理候选密码、批量调度、缓存、fast verifier 和最终 7z.dll 确认。fast verifier 只做低成本判断；命中后仍由 `SevenZipDllVerifier` 最终确认。密码层不执行解压，不判断候选是否应解压。

### extraction

`extraction` 是单归档解压执行层。它消费 `ArchiveTask`、relation 分卷信息、analysis 标注输入和 password resolution，调用 `sevenzip_worker.exe` 通过 `7z.dll` 解压普通文件、`file_range` 或 `concat_ranges` 虚拟输入。它不负责扫描候选、不做批量并发、不做成功后清理。

### repair

`repair` 是损坏结构修复候选生成层。它不再由 analysis 中等置信度直接触发，而是响应 verification 的 `repair` 决策。每个格式一个模块目录，修复模块通过 registry 注册，返回候选文件、虚拟输入或 patch plan。读写二进制必须走 native repair I/O，避免 Python 大文件读写 fallback。

### verification

`verification` 是解压结果校验和候选比较的事实来源。它从 `ArchiveTask`、`ExtractionResult`、`ArchiveState` 和 `PasswordSession` 构建证据，按配置执行 method，返回完整度、文件观察、source integrity、recoverable upper bound 和 decision hint。是否重试、是否清理失败输出、是否进入 repair loop，由 coordinator 决定。

### postprocess

`postprocess` 只处理成功后的清理和扁平化。它可以接收 `contracts.RunContext` 来消费成功归档和扁平化候选，但 `postprocess.internal` 不依赖 coordinator。

### coordinator

`coordinator` 负责流程顺序、递归轮次、批量调度、资源 token、verification retry、repair beam、候选比较和 summary。它不自己识别候选、不执行 7z、不直接实现修复算法。归档清理通过 postprocess 公开动作完成。

### support

`support` 放资源查找、JSON、缓存、路径 helper 和 7z.dll wrapper 绑定。不要把检测策略、输出目录策略、密码解析或清理策略塞进 support。

### native

`native/sunpack_native` 承接跨平台热点：目录扫描、二进制视图、signature prepass、格式 probe、carrier scan、repair I/O、输出 CRC/readability、输出文件索引匹配、deep repair native 实现、密码 fast verifier 等。

`native/sevenzip_password_tester` 承接 Windows 7z.dll ABI：archive probe/test、密码数组尝试、archive state manifest 和 `sevenzip_worker.exe` 解压。

## 禁止清单

以下写法通常表示边界坏掉：

```python
from sunpack.some_domain.internal import ...
```

跨领域不要依赖 internal。补 public facade 或把共享契约移到 `contracts`。

```python
facts = bag._facts
```

不要读取私有状态。使用 `FactBag.to_dict()` 或补公开方法。

```python
from sunpack.coordinator.runner import PipelineRunner  # inside filesystem watcher scheduler
```

`filesystem.watcher` 不直接绑定 coordinator runner，由 app 注入 runner factory。

```python
from sunpack.detection.pipeline.processors.modules... import SOME_RULE_DEFAULT
```

规则层不要依赖 processor 实现模块。共享默认值放到 `detection.pipeline.format_defaults` 或配置声明。

## 重构检查清单

每次改动后至少运行：

```powershell
rg "from sunpack\.[^.]+\.internal" sunpack tests
rg "\._facts|FactBag\._facts" sunpack tests
powershell -ExecutionPolicy Bypass -File scripts\run_ci_tests.ps1
```

人工确认：

- app 是否仍只是 CLI 适配？
- coordinator 是否仍只是编排？
- relation 能力是否通过 `RelationsScheduler` 暴露？
- analysis 是否负责结构和边界，extraction 是否只执行解压？
- verification 是否先于 repair 给出完整度、source integrity 和 repair 决策？
- repair 是否通过 native I/O 处理二进制？
- repair 候选是否重新进入 extraction + verification，而不是直接标记成功？
- support 是否没有混入业务策略？

## 当前结构速览

```text
sunpack/
  app/          CLI 命令、参数、输出和运行时适配
  analysis/     压缩包结构分析和边界标注
  config/       配置读取、校验、归一化和领域配置视图
  contracts/    跨模块数据契约
  coordinator/  pipeline 编排、批量调度和递归
  detection/    候选检测、fact pipeline、规则判断、scene 策略
  extraction/   worker 解压黑盒和解压结果
  filesystem/   通用目录扫描、过滤和 watcher 监控能力
  passwords/    密码候选、调度和 verifier
  postprocess/  解压成功后的清理和扁平化
  relations/    文件关系、分卷和候选组
  rename/       输出命名和临时分卷 staging
  repair/       损坏容器修复流水线
  support/      资源、JSON、缓存、7z.dll ABI 绑定等基础设施
  verification/ 解压结果校验流水线
```
