# 开发边界说明

本文档用于维护 Smart Unpacker 的包结构边界。项目已经把扫描、检测、解压、后处理、配置、密码和 CLI 等职责拆开；后续开发应优先保持这些边界，避免某个模块重新变成“什么都管”的上帝模块。

## 总原则

1. 依赖公开入口，不依赖 `internal`。
2. `coordinator` 只编排流程，不实现领域算法。
3. `app` 只负责 CLI 交互、参数解析和输出适配，不绕过领域模块。
4. `detection` 只判断候选是否应被解压，不执行解压、清理或 CLI 输出。
5. `extraction` 是解压黑盒，对外通过 `ExtractionScheduler` 暴露能力。
6. `passwords` 是密码列表黑盒，对外通过 `smart_unpacker.passwords` 暴露能力。
7. `postprocess` 是后处理黑盒，对外通过 `PostProcessActions` 暴露能力。
8. `config` 接管外部配置读取、配置路径和配置视图。
9. `support` 只放跨领域基础设施，不放业务策略。
10. `contracts` 只放共享数据契约，不放流程控制。

当一个新功能不知道放在哪里时，先问两个问题：

- 这个代码的输入和输出是什么领域对象？
- 它是在“产生事实、推导事实、判断规则、执行解压、执行清理、编排流程、展示 CLI”中的哪一步？

如果回答不清楚，先不要放进 `support` 或 `coordinator`。这两个目录最容易被滥用。

## 推荐依赖方向

高层可以依赖低层，低层不要反向依赖高层。

```text
app
  -> config
  -> coordinator
  -> passwords
  -> support

coordinator
  -> detection
  -> extraction
  -> postprocess
  -> rename
  -> contracts
  -> config 的只读视图

detection
  -> contracts
  -> config.detection_view
  -> filesystem
  -> relations
  -> support 的基础设施

extraction
  -> contracts
  -> passwords
  -> relations
  -> support 的基础设施

postprocess
  -> coordinator.context
  -> support 或标准库

config
  -> support

passwords
  -> support.resources

filesystem / relations / rename
  -> contracts
  -> 标准库
  -> smart_unpacker_native 的窄文件系统 helper

contracts
  -> 标准库
```

允许例外：

- `postprocess.actions.PostProcessActions` 目前接收 `RunContext`，这是为了从协调层消费成功归档和扁平化候选。不要让 `postprocess.internal` 依赖 `coordinator`。
- 测试可以覆盖内部模块，但优先从公开入口测试行为。只有并发调度、错误分类这类窄内部算法，才直接测试 internal。

## 公开入口和私有实现

约定：

- `*/internal/*` 是包内私有实现，只能被同一领域包的公开入口或同一领域内部模块使用。
- 对外调用优先选择 `scheduler.py`、`actions.py`、`__init__.py` 或明确命名的 public 模块。
- 不要从 `app`、`coordinator` 或其他领域直接导入别的领域的 `internal`。
- 不要通过下划线属性读取内部状态，例如 `FactBag._facts`。需要数据时给 contract 增加公开方法。

当前关键公开入口：

| 领域 | 公开入口 | 说明 |
| ---- | -------- | ---- |
| CLI | `smart_unpacker.app.cli.main` | CLI 主入口。 |
| 配置 | `config.loader.load_config` | 读取主配置。 |
| 配置 | `config.schema` | 外部配置字段声明发现、校验和归一化。 |
| 配置 | `config.payload_io` | 读取、写出、展示配置 payload。 |
| 配置 | `config.detection_view` | detection 需要的配置选择器。 |
| 检测 | `detection.DetectionScheduler` | 构建候选、补齐 facts、执行规则判断。 |
| 检测 | `detection.ArchiveTaskProvider` | 将 detection 结果转换为解压任务。 |
| 检测 | `detection.NestedOutputScanPolicy` | 判断解压输出目录是否值得进入下一轮检测。 |
| 检测 | `detection.validate_detection_contracts` | 校验检测插件和配置契约。 |
| 解压 | `extraction.scheduler.ExtractionScheduler` | 解压调度、默认输出目录、调度配置。 |
| 密码 | `smart_unpacker.passwords` | 密码文件读取、内置密码、去重和行解析。 |
| 后处理 | `postprocess.actions.PostProcessActions` | 成功后清理和扁平化。 |
| 文件系统 | `filesystem.directory_scanner.DirectoryScanner` | 目录扫描并生成目录快照。 |
| 关系 | `relations.scheduler.RelationsScheduler` | 分卷、相关文件和候选组关系。 |
| 重命名 | `rename.scheduler.RenameScheduler` | 输出目录命名和冲突处理。 |
| 支撑 | `support.sevenzip_native` | C++ 7z wrapper 的 Python 绑定和缓存入口。 |
| 契约 | `contracts.*` | 跨模块共享的数据结构。 |

## `app`

`app` 是 CLI 适配层。

应该做：

- 定义命令、参数、帮助文本和退出码。
- 将 CLI 参数转换为配置覆盖、密码输入和目标路径。
- 调用 `config` 读取配置。
- 调用 `coordinator` 执行 scan、inspect、extract。
- 调用 `passwords` 展示密码摘要。
- 将结果转换成人类可读输出或 JSON。

不应该做：

- 不直接调用 `detection.pipeline` 内部插件。
- 不直接调用 `extraction.internal`。
- 不直接读取 `FactBag._facts`、`RunContext` 内部实现细节。
- 不自己实现配置文件查找、密码文件解析、目录扫描或 7-Zip 查找。

典型边界：

- 需要 scheduler profile 的展示数据时，走 `ExtractionScheduler.scheduler_profile_config()`。
- 需要 facts 字典时，走 `FactBag.to_dict()`。
- 需要读取密码文件时，走 `smart_unpacker.passwords.read_password_file()`。

## `config`

`config` 接管所有外部配置读取和配置视图。

应该做：

- 查找默认配置、用户指定配置和资源配置。
- 读取 JSON 配置。
- 校验配置 payload。
- 提供针对不同领域的只读选择器，例如 `detection_view.py`。
- 读取 CLI 语言等 CLI 配置项。

不应该做：

- 不执行 detection、extraction 或 postprocess。
- 不生成 `ArchiveTask`。
- 不把领域默认策略散落到 CLI。

边界说明：

- 通用资源路径查找在 `support.resources`。
- 配置路径语义在 `config.paths` 和 `config.loader`。
- detection 只通过 `config.detection_view` 读取它关心的配置，不直接在 detection 内部散落 selector。

## `contracts`

`contracts` 是跨模块共享的数据契约层。

包含：

- `detection.FactBag`
- `filesystem.DirectorySnapshot`、`FileEntry`
- `rules.RuleDecision`、`RuleEffect`
- `tasks.ArchiveTask`、`RenameInstruction`
- `results.RunSummary`

应该做：

- 定义稳定字段和小型访问方法。
- 提供安全的只读导出方法，例如 `FactBag.to_dict()`。

不应该做：

- 不读取磁盘。
- 不调用 7-Zip。
- 不执行规则判断。
- 不了解 CLI 或 coordinator。

如果外部模块需要 contract 内部数据，不要直接访问下划线字段；给 contract 增加明确的公开方法。

## `coordinator`

`coordinator` 是流程编排层。它连接 detection、extraction、postprocess、rename 和 recursion，但不拥有这些领域算法。

主要模块：

- `runner.py`：完整 extract pipeline 的总调度。
- `scanner.py`：scan 命令的编排。
- `inspector.py`：inspect 命令的编排，只读 detection facts 和 decision。
- `task_scan.py`：调用 detection 的 `ArchiveTaskProvider`，不持有候选识别规则。
- `extraction_batch.py`：批量解压流程编排。
- `output_scan.py`：递归输出扫描策略的兼容门面；实际策略在 detection。
- `space_guard.py`：决定什么时候触发清理；实际清理由 `PostProcessActions` 执行。
- `recursion.py`：递归轮次策略。
- `reporting.py`：运行摘要输出。
- `context.py`：跨轮运行状态。

应该做：

- 决定阶段顺序。
- 把一个阶段的输出传给下一个阶段。
- 管理递归轮次、运行上下文和失败任务汇总。
- 调用领域公开入口。

不应该做：

- 不自己扫描目录树生成 `DirectorySnapshot`，应调用 `filesystem.DirectoryScanner` 或 detection 公开能力。
- 不自己判断文件是不是压缩包，应调用 `DetectionScheduler`。
- 不自己计算默认输出目录，应调用 `ExtractionScheduler.default_output_dir_for_task()`。
- 不自己执行 7-Zip，应调用 `ExtractionScheduler`。
- 不直接删除归档文件，应调用 `PostProcessActions.cleanup_archive_file()` 或 `apply()`。
- 不读取 `FactBag._facts`。
- 不导入 `detection.pipeline.*` 的具体规则来做判断。

递归输出扫描的特殊边界：

- `detection.NestedOutputScanPolicy` 可以使用 `detection.scene.directory_context` 判断输出目录是否像游戏、程序或其他强场景目录。
- 它的职责只是决定“输出目录是否加入下一轮递归扫描”。
- 它不生成 detection pipeline facts，也不参与规则打分。
- coordinator 只调用该公开策略，不自己判断文件是否像归档候选。

## `detection`

`detection` 负责回答一个问题：候选文件或目录是否应该进入解压任务。

公开入口：

- `DetectionScheduler.detect_targets()`
- `DetectionScheduler.build_candidate_fact_bags()`
- `DetectionScheduler.evaluate_bag()`
- `DetectionScheduler.evaluate_pool()`
- `validate_detection_contracts()`

内部结构：

```text
detection/
  scheduler.py
  validation.py
  internal/
    target_groups.py
    target_scan.py
  pipeline/
    facts/
    processors/
    rules/
  scene/
```

### `detection.pipeline.facts`

Facts 层语义必须严格：

```text
输入：扫描的文件路径或文件所在目录
输出：初等 facts
```

Facts 层只做“观察”和“采集”，不做高阶判断。

可以做：

- 读取文件路径、大小、扩展名。
- 读取少量 magic bytes。
- 扫描候选目录并提取 scene marker candidates。

不可以做：

- 不根据分数判断是否解压。
- 不调用规则。
- 不把多个 facts 组合成结论性事实。
- 不执行解压或清理。

示例：

- `file_facts.py`：文件路径、文件名、扩展名、大小等基础事实。
- `magic_bytes.py`：文件头 bytes。
- `scene_markers.py`：从候选目录扫描得到初等 scene marker candidates。

### `detection.pipeline.processors`

Processors 层语义必须严格：

```text
输入：初等 facts
输出：高等 facts
```

Processors 层负责把已采集事实推导成更有语义的事实。

可以做：

- 根据 magic bytes 和结构读取推导 archive identity。
- 根据 ZIP 结构判断容器类型。
- 根据 scene marker candidates 生成 scene context。
- 调用 7-Zip 做 probe 或 validation，并把结果写成 facts。

不可以做：

- 不返回最终 should_extract。
- 不处理规则分数。
- 不删除文件、不解压文件。

### `detection.pipeline.rules`

Rules 层语义必须严格：

```text
输入：facts
输出：判断
```

Rules 只读 facts 和自身配置，输出硬停止、加减分或确认结果。

规则层分三类：

- `precheck`：遇到明确拒绝或明确接受的场景时终止后续检测。
- `scoring`：给候选加分或扣分。
- `confirmation`：对中间态候选做进一步确认。

不可以做：

- 不扫描目录生成新候选。
- 不直接调用外部清理或解压。
- 不把 CLI 输出逻辑写进规则。

如果规则需要额外 facts，通过 `required_facts` 或 `fact_requirements` 声明，让 scheduler 补齐。

### `detection.scene`

`scene` 是 detection 的公共基础设施，不是 pipeline 阶段。

当前结构：

```text
detection/scene/
  definitions.py
  markers.py
  context.py
  directory_context.py
```

职责：

- `definitions.py`：scene 规则 payload 和配置读取。
- `markers.py`：`DirectorySnapshot -> marker set` 的纯算法。
- `context.py`：marker candidates 或 marker set 到 scene context 的纯算法。
- `directory_context.py`：给非 pipeline 调用方使用的目录场景检测能力。

边界：

- facts 层可以调用 `markers.py`，因为它需要从目录扫描结果产生初等 marker facts。
- processors 层可以调用 `context.py`，因为它需要从 marker facts 推导 context facts。
- coordinator 的 `output_scan.py` 可以调用 `directory_context.py`，因为它只需要一个公共基础设施能力来保护输出目录递归扫描。
- `scene` 不应该依赖 `coordinator`、`extraction` 或 `postprocess`。

## `filesystem`

`filesystem` 是文件系统扫描基础设施。

当前公开能力：

- `DirectoryScanner.scan(path)` 生成 `DirectorySnapshot`。
- `DirectoryScanner` 使用 `smart_unpacker_native` 目录遍历；原生层只返回基础条目元数据，Python 层仍负责 contract 构建。过滤器必须能映射到原生层支持的参数，否则应显性失败。

应该做：

- 遍历目录。
- 生成稳定的文件条目结构。
- 保持和 detection 规则无关。
- 把原生扫描当作实现细节，行为语义仍以 `DirectoryScanner` 为准。

不应该做：

- 不判断文件是否应该解压。
- 不执行 scene 高阶判断。
- 不创建 `ArchiveTask`。

`detection` 使用它获得目录快照；`coordinator` 如果需要纯目录扫描，也应优先用它，而不是各自手写一套扫描。

## `relations`

`relations` 负责文件之间的关系，尤其是分卷、候选组和相关文件。

应该做：

- 识别多分卷归档的主文件和成员。
- 为 detection 或 extraction 提供候选组。
- 保持和规则打分、CLI 输出无关。
- 可以使用 `smart_unpacker_native.list_regular_files_in_directory` 加速目录文件枚举。

不应该做：

- 不决定 should_extract。
- 不执行解压。
- 不清理文件。
- 不把分卷命名规则、head/member 选择或 fuzzy volume 语义搬到 Rust，除非先有清晰的公开契约和回归测试。

## `extraction`

`extraction` 是解压黑盒。

公开入口：

- `ExtractionScheduler`
- `ExtractionResult`

内部实现：

```text
extraction/internal/
  concurrency.py
  errors.py
  executor.py
  metadata.py
  output_paths.py
  password_manager.py
  password_resolution.py
  split_stager.py
```

应该做：

- 管理 7-Zip 路径。
- 解析密码尝试顺序。
- 处理分卷 staging。
- 探测元数据和编码。
- 计算默认输出目录。
- 执行 7-Zip 解压。
- 分类解压错误。
- 管理并发调度。

不应该做：

- 不扫描目标目录寻找候选。
- 不判断候选是否应该解压。
- 不做成功后的归档清理或扁平化。
- 不依赖 CLI。

外部调用规则：

- 需要解压多个任务，调用 `ExtractionScheduler.extract_tasks()` 或 `extract_all()`。
- 需要单个任务输出目录，调用 `ExtractionScheduler.default_output_dir_for_task()`。
- 需要 scheduler profile 展示配置，调用 `ExtractionScheduler.scheduler_profile_config()`。
- 不从外部导入 `extraction.internal.*`。

## `passwords`

`passwords` 是密码列表黑盒。

公开入口在 `smart_unpacker/passwords/__init__.py`：

- `DEFAULT_BUILTIN_PASSWORDS`
- `get_builtin_passwords()`
- `read_password_file()`
- `parse_password_lines()`
- `dedupe_passwords()`

应该做：

- 读取内置密码资源。
- 读取用户密码文件。
- 解析密码文本行。
- 去重并保持顺序。

不应该做：

- 不调用 7-Zip。
- 不判断密码是否正确。
- 不处理 CLI 参数。

密码是否能解开归档属于 `extraction.internal.password_resolution`；密码列表如何获得属于 `passwords`。

## `postprocess`

`postprocess` 是解压成功后的动作黑盒。

公开入口：

- `PostProcessActions`

内部实现：

```text
postprocess/internal/
  cleanup.py
  flatten.py
```

应该做：

- 成功后按配置保留、回收站或删除原归档。
- 扁平化单一顶层输出目录。
- 向 coordinator 暴露简单动作接口。

不应该做：

- 不决定哪些文件应该解压。
- 不执行解压。
- 不扫描递归轮次。

`space_guard.py` 的边界：

- `space_guard` 决定什么时候需要释放空间。
- 真正的 cleanup 通过 `PostProcessActions.cleanup_archive_file()` 调用。
- 不允许 `coordinator` 直接导入 `postprocess.internal.cleanup`。

## `rename`

`rename` 负责输出目录命名和冲突规避。

应该做：

- 根据 `ArchiveTask` 生成输出目录重命名指令。
- 处理重名、后缀和命名稳定性。

不应该做：

- 不检测是否是归档。
- 不执行解压。
- 不做后处理清理。

## `support`

`support` 是跨领域基础设施，不是业务兜底目录。

当前职责：

- `resources.py`：资源路径查找、7-Zip 查找、路径候选去重。
- `json_format.py`：JSON 读写和格式化。
- `external_command_cache.py`：外部命令和文件指纹缓存。
- `sevenzip_native.py`：C++ 7z wrapper 的 Python ABI 绑定、状态结构和文件指纹缓存入口。

可以放进 `support` 的代码：

- 不知道任何业务对象的纯基础设施。
- 多个领域都需要的通用资源查找、缓存、JSON 工具。
- 不依赖 `detection`、`extraction`、`coordinator` 等领域包。
- 外部 ABI 适配层，例如 7z.dll wrapper 的 Python 绑定；业务解释仍留在调用领域。

不应该放进 `support` 的代码：

- 场景识别算法。它属于 `detection.scene`。
- 密码解析。它属于 `passwords`。
- 输出目录策略。它属于 `extraction`。
- 清理策略。它属于 `postprocess`。
- 扫描归档候选。它属于 `detection` 或 `coordinator` 调度。

## `native`

`native` 放项目自带原生组件。原生层只承接明确的性能热点或外部 ABI 适配，不拥有业务决策。

当前组件：

- `native/smart_unpacker_native`：Rust/PyO3 扩展，负责跨平台热点，例如目录扫描、magic 搜索、轻量格式结构解析、PE overlay 解析和关系分组中的单目录文件枚举。
- `native/sevenzip_password_tester`：Windows C++ wrapper，负责通过 `7z.dll` 实现 archive probe、archive test 和密码数组尝试。

边界：

- Python 层仍是事实形状、规则语义、分卷关系语义和任务调度的权威实现。
- Rust helper 应保持小而纯，不直接读取配置、不产生最终 decision。
- C++ 7z wrapper 只封装 7-Zip COM/ABI 细节，不依赖 detection、extraction 或 CLI 业务对象。
- 最终解压仍通过 `7z.exe x`，不要让 wrapper 和解压调度强耦合。

## 新功能放置指南

### 新增一种检测事实

放置：

- 初等事实：`detection/pipeline/facts/collectors/`
- 高等事实：`detection/pipeline/processors/modules/`
- fact schema：`detection/pipeline/facts/schema.py` 或对应注册逻辑

要求：

- collector 输入文件路径或目录扫描结果，输出初等 facts。
- processor 输入 facts，输出推导 facts。
- 不在 collector 或 processor 里返回最终判断。

### 新增一条检测规则

放置：

- `detection/pipeline/rules/precheck/`
- `detection/pipeline/rules/scoring/`
- `detection/pipeline/rules/confirmation/`

要求：

- 继承 `RuleBase`。
- 使用 `register_rule()` 注册。
- 声明 `required_facts` 或 `fact_requirements`。
- 配置字段写 `config_schema`。
- 文档同步更新 `docs/rule_plugins.md` 和 `smart_unpacker_config.json`。

### 新增解压行为

优先判断它属于哪类：

- 7-Zip 命令、密码、分卷、错误、并发：放在 `extraction/internal/`，由 `ExtractionScheduler` 暴露。
- 默认输出路径策略：放在 `extraction/internal/output_paths.py`，由 `ExtractionScheduler.default_output_dir_for_task()` 暴露。
- 成功后清理或扁平化：放在 `postprocess`。
- 递归是否继续扫描：放在 `coordinator`。

### 新增 CLI 参数

放置：

- parser：`app/cli_parsers.py`
- command handler：`app/commands/*.py`
- 参数转换：`app/cli_runtime.py` 或对应 command 模块
- 配置读取：`config`

要求：

- CLI 参数只转换为 config 或调用公开入口。
- 不把领域算法写进 CLI。

### 新增配置项

放置：

- 默认配置：`smart_unpacker_config.json`
- 外部配置字段声明：`config/fields/` 下按领域拆分的字段声明文件。
- 字段发现和归一化入口：`config.schema`
- 读取：`config.loader`
- 领域视图：必要时新增或扩展 `config.*_view.py`
- 校验：普通外部字段走 `config.schema`；规则插件字段走领域自带 validator
- 文档：`docs/configuration.md`

要求：

- 外部配置语法、默认值和归一化函数必须在一个 `ConfigField` 声明里完成。
- 领域模块可以声明自己的配置字段，但业务运行时应消费 `load_config()` 或 `normalize_config()` 后的内部配置形状。
- 领域模块不要直接到处写 `config.get(...).get(...)` selector。
- 如果多个模块需要同一段配置，抽成 config view。

## 禁止清单

以下写法通常表示边界正在坏掉：

```python
from smart_unpacker.extraction.internal.concurrency import ...
```

外部模块不应依赖 extraction internal。用 `ExtractionScheduler` 暴露能力。

```python
facts = dict(bag._facts)
```

不要读私有字段。用 `bag.to_dict()`。

```python
from smart_unpacker.postprocess.internal.cleanup import ArchiveCleanup
```

coordinator 不应直接调用 postprocess internal。用 `PostProcessActions`。

```python
from smart_unpacker.detection.pipeline.rules.scoring.extension import ExtensionRule
```

coordinator 或 app 不应直接拿具体规则做判断。用 `DetectionScheduler`。

```python
os.walk(...)  # 在多个领域里重复实现候选扫描
```

如果目的是目录快照，用 `filesystem.DirectoryScanner`。如果目的是候选检测，用 `DetectionScheduler`。

## 重构检查清单

每次新增或移动代码后，至少检查：

```powershell
rg "from smart_unpacker\.[^.]+\.internal" smart_unpacker tests
rg "\._facts|FactBag\._facts" smart_unpacker tests
pytest
```

检查解释：

- `internal` 搜索应只剩同一领域包内部引用，或少量明确需要的内部算法测试。
- `_facts` 搜索应只出现在 `contracts/detection.py` 内部实现。
- 全量测试应通过。

更严格的人工检查：

- `app` 是否只做 CLI 适配？
- `coordinator` 是否只做调度？
- `detection.pipeline.facts` 是否只输出初等 facts？
- `detection.pipeline.processors` 是否只输出高等 facts？
- `detection.pipeline.rules` 是否只基于 facts 输出判断？
- `extraction` 是否仍然是黑盒？
- `postprocess` cleanup 是否只通过公开接口调用？
- `support` 里是否混入了业务策略？

## 当前结构速览

```text
smart_unpacker/
  app/          CLI 命令、参数、输出和运行时适配
  config/       配置读取、配置路径、配置校验和领域配置视图
  contracts/    跨模块数据契约
  coordinator/  pipeline 编排和运行上下文
  detection/    候选检测、fact pipeline、规则判断、scene 基础设施
  extraction/   解压黑盒和解压结果
  filesystem/   通用目录扫描
  passwords/    密码列表黑盒
  postprocess/  解压成功后的清理和扁平化
  relations/    文件关系、分卷和候选组
  rename/       输出命名
  support/      资源、JSON、缓存等跨领域基础设施
```

维护这个结构的核心目标是：让每个目录的名字都能回答“这里为什么存在”。当代码不确定该放哪时，先根据输入输出和领域语义定位，再补公开接口，而不是跨包拿 internal 或把逻辑塞进 coordinator。
