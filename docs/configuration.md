# 配置文件说明

常用配置文件为 `sunpack_config.json`，只保留最常改的字段。完整高级配置文件为 `sunpack_advanced_config.json`，保留全部可调字段。

运行时会先读取 `sunpack_advanced_config.json`，再用 `sunpack_config.json` 覆盖同名字段：对象字段递归合并，数组和普通值整体覆盖。也就是说，简化配置优先级更高；用户可以把任意高级字段搬进 `sunpack_config.json` 接管它，也可以删掉字段让高级配置兜底。

源码运行时通常读取仓库根目录或当前工作目录中的配置；打包版本优先读取可执行文件旁边的外部配置，因此用户可以在不重新打包的情况下调整行为。

检查配置：

```powershell
python sunpack.py config validate
```

查看配置：

```powershell
python sunpack.py config show
```

## 顶层结构

```json
{
  "cli": {},
  "thresholds": {},
  "recursive_extract": "*",
  "nested_extraction_policy": {},
  "post_extract": {},
  "filesystem": {},
  "performance": {},
  "analysis": {},
  "verification": {},
  "repair": {},
  "detection": {}
}
```

## cli

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `language` | `str` | CLI 语言。`zh` 启用中文，其它值回退英文。 |

## thresholds

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `archive_score_threshold` | `int` | `6` | detection 分数达到该值时生成解压任务。 |
| `maybe_archive_threshold` | `int` | `3` | 分数达到该值但低于归档阈值时进入确认层。 |

确认层处理 `maybe_archive_threshold <= score < archive_score_threshold` 的中间可疑区间。结构事实、embedded payload、7z probe/test 和场景保护会共同影响最终决策。

## recursive_extract

| 值 | 说明 |
| --- | --- |
| `*` | 无限递归，内部上限为 999 轮。 |
| 正整数 | 固定递归轮数。 |
| `?` | 每轮递归后询问是否继续。 |

递归轮次只表示最多允许继续扫描多少轮。第一轮完全按用户选择的文件或目录扫描范围执行，不做目录语义门控。第一轮完成后，coordinator 会用 `NestedOutputScanPolicy` 发现输出中的压缩包；从第二轮开始，`nested_extraction_policy` 在实际分析和解压前做目录语义授权。

CLI 可用 `--recur` 临时覆盖。

## nested_extraction_policy

该策略批量判断自动从解压结果中发现的压缩包是否像用户语义上的独立归档。它不会弹出确认，也不会减少 detection 的完整候选发现；被拒绝的候选在进入 analysis、密码处理和实际解压前停止。用户请求的第一轮扫描始终绕过该策略；第二轮起所有候选统一判断，包括输出根目录第一层的候选。

判断使用同一次 filesystem 枚举产生的过滤前原始快照，因此黑名单、大小过滤等不会把普通游戏文件从目录上下文中隐藏。统计和候选合并在 Rust 中一次完成，不会为每个嵌套压缩包重复扫描目录。

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | 是否启用解压前批量授权。 |
| `other_project_tolerance` | `float` | `2` | 有效非候选项目达到此数量时，项目纯净度为 `0.5`。 |
| `byte_ratio_weight` | `float` | `0.5` | 调和评分中压缩包字节占比的权重，必须严格位于 `0` 和 `1` 之间。 |
| `minimum_authorization_score` | `float` | `0.65` | 局部和根目录授权评分均需达到的最低值。 |
| `minimum_archive_byte_ratio` | `float` | `0.1` | 局部或根目录候选字节占比低于此值时直接拒绝。 |
| `hard_maximum_other_projects` | `int` | `64` | 局部或根目录有效非候选项目超过此值时直接拒绝。 |

设候选字节占比为 `B`、有效非候选项目数为 `O`、容忍度为 `K`，项目纯净度为 `C = 1 / (1 + (O / K)²)`，最终使用加权调和评分 `S = 1 / (w / B + (1 - w) / C)`。`S` 是位于 `0..1` 的确定性置信分，不是在标注数据上校准过的真实概率。该模型会让大小或目录结构中的弱项显著降低结果，避免巨大资源包用字节优势掩盖大量普通文件。

候选位于更深目录时，以扫描根下包含它的第一个目录作为局部语义子树，并同时统计完整输出根；最终取两个评分中的较低值。普通非候选文件逐个计数，不含候选的首层旁支目录额外计数；候选路径上的连续包装目录不计数。同一范围里的多个压缩包统一聚合，分卷成员去重求和。拒绝结果以 `nested_extraction_policy` 策略跳过记录在运行摘要中，不作为解压失败。

## pipeline

`pipeline` 控制进程级常驻 Engine 的入口队列和自动微批，不改变单个压缩包的检测、验证或修复策略。

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `batch_window_seconds` | `float` | `0` | 首个请求到达后继续收集兼容请求的最大时间；`0` 表示到达后立即调度。 |
| `max_batch_requests` | `int` | `64` | 一个微批最多包含的提交请求数。 |
| `queue_capacity` | `int` | `4096` | 入口队列上限；达到上限时提交方产生背压。 |

CLI 在当前命令结束后关闭 Engine；watch 在服务生命周期内保持同一个 Engine、资源调度器和 7-Zip worker pool。入口队列、分析、预检、资源分析和解压共享同一份 CPU/IO/内存预算；调度反馈跨微批保留，到 Engine 关闭时统一保存。

## post_extract

| 字段 | 类型 | 可选值 | 说明 |
| --- | --- | --- | --- |
| `archive_cleanup_mode` | `str` | `d`、`r`、`k` | 成功后如何处理原归档：删除、回收站、保留。 |
| `flatten_single_directory` | `bool` | `true` / `false` | 解压结果只有一个顶层目录时，是否把内容提升一层。 |

建议默认用 `r`，避免误删原始归档。

## filesystem

### directory_scan_mode

| 值 | 说明 |
| --- | --- |
| `*` | 递归扫描目标目录及子目录。 |
| `-` | 只扫描目标目录第一层文件。 |

该设置只影响输入目录扫描范围，不影响解压后的递归轮次。

### scan_filters

`scan_filters_enabled` 是扫描过滤器总开关。设为 `false` 时保留 `scan_filters` 配置但不应用任何过滤器，适合临时排查是否被黑名单、大小范围、修改时间范围或目录剪枝挡掉。

扫描过滤器在目录遍历阶段执行，被过滤的条目不会进入 relation、detection 或 analysis。

`scan_filters` 按配置数组中的顺序执行；第一个启用的过滤器就第一个处理扫描条目。`whitelist` 默认关闭，启用后文件必须命中 whitelist 才会继续进入它后面的过滤器；字段与 `blacklist` 一致，但语义是“允许”。例如：

```json
{
  "name": "whitelist",
  "enabled": false,
  "path_globs": ["archives/**"],
  "prune_dir_globs": ["archives"],
  "allowed_files": ["sample.zip"],
  "allowed_extensions": [".zip", ".7z"]
}
```

`whitelist` 使用 `allowed_files` 和 `allowed_extensions` 表示允许的完整文件名和扩展名。每个 whitelist 字段为空时表示该维度不限制；多个非空字段会同时作为约束。`blacklist` 使用 `blocked_files` 和 `blocked_extensions` 表示禁止的完整文件名和扩展名。

`directory_prune` 的 `prune_dir_globs` / `path_globs` 在原生目录遍历阶段执行；命中的目录不会入栈，其整个子树也不会进入后续过滤器。`prune_dir_globs` 匹配任意层级的目录名，`path_globs` 匹配相对于扫描根的路径。`blacklist` 只负责具体文件名和扩展名过滤。

`blacklist` 常用字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `blocked_files` | `list[str]` | 完整文件名精确匹配，例如 `Thumbs.db`、`desktop.ini`。 |
| `blocked_extensions` | `list[str]` | 阻止扫描的文件扩展名。 |

`size_range` 用文件大小限制 filesystem 输出。只有落在配置范围内的文件才会进入 relation、detection 或 analysis；目录不受该过滤器影响。推荐写数学不等式，`r` 表示文件大小：

```json
{"name": "size_range", "enabled": true, "range": "1 MB < r < 10 MB"}
```

大小单位支持 `B`、`KB`、`MB`、`GB`、`TB` 和 `KiB`、`MiB`、`GiB`、`TiB`，按 1024 进位。也兼容旧的原始范围字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `gt` / `greater_than` | `int` | 文件大小必须大于该值。 |
| `gte` / `greater_than_or_equal` | `int` | 文件大小必须大于等于该值。 |
| `lt` / `less_than` | `int` | 文件大小必须小于该值。 |
| `lte` / `less_than_or_equal` | `int` | 文件大小必须小于等于该值。 |
| `eq` / `equal` | `int` | 文件大小必须等于该值。 |

`mtime_range` 用文件修改时间限制 filesystem 输出，推荐写数学不等式，`d` 表示文件修改时间：

```json
{"name": "mtime_range", "enabled": false, "date": "20260430 01:40 > d > 20250320 01:30"}
```

日期值支持纳秒时间戳、ISO 时间字符串，以及 `YYYYMMDD HH:MM` / `YYYYMMDD HH:MM:SS` / `YYYYMMDD`。旧的 `gt/gte/lt/lte/eq` 字段仍兼容。

目录扫描使用 Rust `scan_directory_snapshot`。过滤器无法映射到 native 参数时会显性报错，不做 Python fallback。

## performance

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `scheduler_profile` | `str` | `auto`、`conservative` 或 `aggressive`。 |
| `scheduler_idle_decay_seconds` | `int` / `float` | 流水线持续空闲多久后逐步将动态并发限制和短期反馈衰减到初始状态；不会清除持久 profile 校准。 |
| `max_extract_task_seconds` | `int` / `float` | 单个解压任务总时长上限，`0` 表示不限。 |
| `process_no_progress_timeout_seconds` | `int` / `float` | worker 无进展超时，`0` 表示不限。 |
| `process_sample_interval_ms` | `int` / `float` | worker 进程采样间隔。 |
| `persistent_workers` | `bool` | 是否复用 worker 进程。 |
| `profile_calibration_*` | 多种 | 并发调度 profile 的运行时反馈调节。 |
| `resource_guard` | `dict` | 可选资源护栏，用 analysis 估算的文件数、解包大小、压缩比等限制任务。 |

`auto` 会根据 CPU 和内存选择保守或激进档。配置文件中的超时会覆盖 profile 内置值。
资源调度器只在存在 pipeline backlog、已注册 workload 或活跃 worker 时采集 CPU、内存和磁盘指标；Engine 空闲时会阻塞等待新工作，不进行周期采样。CLI、右键菜单和 watch 共用这一行为。

`resource_guard` 当前常用字段：

| 字段 | 说明 |
| --- | --- |
| `enabled` | 是否启用资源护栏。 |
| `max_file_count` | 归档条目数超过该值时阻止解压，`0` 表示不限。 |
| `max_total_unpacked_size` | 估算总解包大小上限，字节，`0` 表示不限。 |
| `max_largest_item_size` | 单个最大条目上限，字节，`0` 表示不限。 |
| `max_compression_ratio` | 压缩比上限，`0` 表示不限。 |

## watch

`watch` 配置控制 `sunpack watch` 的默认行为；CLI 参数仍可临时覆盖对应值。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `cold_start_seconds` | `float` | 文件首次进入活跃态、尚无写入间隔样本时的等待时间，默认 1 秒。设为 `0` 会关闭动态等待。旧字段 `quiet_seconds` 仍作为该字段的兼容别名。 |
| `quiet_min_seconds` | `float` | 取得首个有效间隔后，动态静默时间的下限，默认 2.5 秒。它可以高于冷启动时间。 |
| `quiet_max_seconds` | `float` | 动态静默时间上限，默认 180 秒。 |
| `recursive` | `bool` | 是否递归监控目录。 |
| `initial_scan` | `bool` | 启动 watcher 时是否扫描已有文件。 |
| `max_folders` | `int` | 单次 watch 接受的最大路径数量。 |
| `observer_stop_timeout_seconds` | `float` | 停止 watchdog observer 时等待线程退出的超时。 |

没有活跃文件或待处理密码重试时，watch 服务会无限等待 watchdog 或控制事件；只有静默期和 debounce 尚未到期时才设置一次性 deadline。

watch 不按扩展名或下载器类型推测下载状态。`created`、`moved`、`modified` 事件使输入进入活跃态；首次使用 `cold_start_seconds`，取得首个有效内容变化间隔后立即进入不低于 `quiet_min_seconds` 的动态区间，随后按该文件最近 12 次实际内容变化的最大间隔调整。长间隔会立即拉长，缩短时每次只向目标移动一部分，最终受 `quiet_min_seconds` 和 `quiet_max_seconds` 限制。只有 size 或 mtime 变化的事件参与间隔学习，但其他内容事件仍会重置当前静默计时。每个活跃周期只触发一次主流程；普通成功、部分成功和失败都不会自行重试。新分卷到达或密码源变化会把受影响的输入重新置为活跃态。

watch 的试解压输出位于监控根目录下的 `.sunpack_watch_probes`。该顶层目录在 watcher 运行和多次尝试之间保持存在；启动恢复以及每次尝试结束时只清理其内部工作内容，避免监控目录因为顶层临时目录反复创建、删除而刷新。

## extraction

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `write_progress_manifest` | `bool` | 是否把内部 progress manifest 写成输出目录中的 `.sunpack/extraction_manifest.json`；默认只保留在内存里供 verification/repair 使用。 |

## analysis

`analysis` 是 detection 和 extraction 之间的结构分析层，也会在 repair beam 候选评估中复用。它输出格式证据、边界、损坏标志、分卷视图和可供 worker 使用的虚拟输入。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `enabled` | `bool` | 是否启用 analysis。 |
| `task_parallel` | `bool` | 批量任务是否并行 analysis。 |
| `task_max_workers` | `int` | 批量 analysis worker 上限。 |
| `cache_size` | `int` | batch 级 analysis 结果缓存数量。 |
| `parallel` | `bool` | 单个输入内是否并行跑格式模块。 |
| `max_workers` | `int` | 单输入格式模块并发上限。 |
| `max_concurrent_reads` | `int` | 单视图并发读取上限。 |
| `shared_cache_mb` | `int` | 二进制视图共享读缓存。 |
| `max_read_mb_per_archive` | `int` / `null` | 单归档最多读取大小，`null` 表示不限。 |
| `prepass` | `dict` | signature prepass 配置。 |
| `fuzzy` | `dict` | fuzzy binary profile 配置。 |
| `thresholds.extractable_confidence` | `float` | analysis 认为可直接抽取的置信度。 |
| `thresholds.repair_confidence` | `float` | 保留给损坏/修复倾向判断的置信度参考。 |
| `modules` | `list[dict]` | ZIP/RAR/7z/TAR/压缩流等结构模块开关和参数。 |

重要行为：

- analysis 的中等置信度不再直接触发 repair。流程会先尝试 extraction，再由 verification 判断是否需要 repair。
- batch cache key 包含 patch digest、路径、大小、mtime 和分卷 mtimes，可避免 repair loop 和 beam 候选重复分析同一输入。
- 结构读取和大文件 I/O 走 Rust binary view，不保留 Python 大文件解析 fallback。

常见 module 参数：

| 模块 | 常用字段 |
| --- | --- |
| `zip` | `max_cd_entries_to_walk` |
| `rar` | `max_blocks_to_walk` |
| `seven_zip` | `max_next_header_check_bytes` |
| `tar` | `max_entries_to_walk` |
| `gzip` / `bzip2` / `xz` / `zstd` / `tar_*` | `max_probe_bytes` |

## verification

`verification` 不再是简单分数阈值模型。它会汇总多个 method 的观察结果，计算完整度、文件状态、source integrity、recoverable upper bound 和下一步决策。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `enabled` | `bool` | 是否启用解压结果校验流水线。 |
| `max_retries` | `int` | verification 失败后的普通重试次数。 |
| `cleanup_failed_output` | `bool` | 重试前是否清理失败输出目录。 |
| `accept_partial_when_source_damaged` | `bool` | 源归档损坏时是否允许接受部分恢复结果。 |
| `partial_min_completeness` | `float` | 部分恢复最低完整度。 |
| `complete_accept_threshold` | `float` | complete 判定完整度阈值。 |
| `partial_accept_threshold` | `float` | partial 判定完整度阈值。 |
| `retry_on_verification_failure` | `bool` | verification 失败时是否允许普通重试。 |
| `methods` | `list[dict]` | 有序 verification method 列表。 |

旧配置项 `initial_score`、`pass_threshold`、`fail_fast_threshold` 已不是当前模型的一部分，不应再写入配置。

内置 method：

| 方法 | 说明 |
| --- | --- |
| `extraction_exit_signal` | 消费 worker 状态、诊断和 progress manifest。 |
| `output_presence` | 检查输出目录是否存在、是否为空，并合并 worker manifest 进度。 |
| `expected_name_presence` | 用 detection/analysis 提供的条目名样本检查输出命中情况。 |
| `manifest_size_match` | 用归档条目数和原始大小估算完整度。 |
| `archive_test_crc` | 用 7z.dll 读取归档状态，并由 Rust 扫描输出、建立 path/basename 索引、计算 CRC 和覆盖率。 |
| `sample_readability` | 用 Rust 抽样读取输出文件头尾，确认产物基本可读。 |

`archive_test_crc` 和 `sample_readability` 当前默认启用。前者已经 Rust 化输出索引和 CRC 比较，适合大量小文件场景。

## repair

`repair` 只响应 verification 的 `repair` 决策。它生成候选或 patch plan，候选必须重新 extraction + verification，由比较器决定是否接受、继续修复或停止。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `enabled` | `bool` | 是否启用 repair 层。 |
| `workspace` | `str` | repair 候选工作目录。 |
| `keep_candidates` | `bool` | 是否保留候选文件。 |
| `max_modules_per_job` | `int` | 单个 repair job 最多尝试多少模块。 |
| `max_attempts_per_task` | `int` | 兼容字段；当前主要使用 repair round 限制。 |
| `max_repair_rounds_per_task` | `int` | 单任务 repair loop 上限。 |
| `max_repair_seconds_per_task` | `int` / `float` | 单任务 repair 总耗时上限。 |
| `max_repair_generated_files_per_task` | `int` | 单任务最多生成候选文件数。 |
| `max_repair_generated_mb_per_task` | `int` / `float` | 单任务最多生成候选总大小。 |
| `stages` | `dict` | `targeted`、`safe_repair`、`deep` 阶段开关。 |
| `safety` | `dict` | `allow_unsafe`、`allow_partial`、`allow_lossy`。 |
| `deep` | `dict` | deep 模块候选数、输入/输出大小、条目数和验证预算。 |
| `auto_deep` | `dict` | targeted/safe 无改进时自动放行少量 deep 候选。 |
| `beam` | `dict` | patch plan beam 搜索和候选评估上限。 |
| `policy` | `dict` | 内置 diagnosis HGT 与 repair policy transformer 的运行控制。 |
| `modules` | `list[dict]` | 显式 repair 模块开关。 |

### policy

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | 是否启用内置双模型 repair policy。 |
| `strict_model_errors` | `bool` | `false` | 模型推理异常时是否直接抛出；关闭时记录模型错误并返回 unavailable。 |
| `graph_stop_stale_patience` | `int` | `100` | repair 图连续多少次没有最佳状态提升后强制 stop。 |

双模型由 `sunpack.repair.model.RepairModelRuntime` 直接管理。`provider_package`、`step_mode`、`fallback_to_selector` 和 `disable_beam_when_model_active` 均已删除，配置中出现会直接报错。模型资产由根目录 `models/manifest.json` 管理，可用 `python -m pytest tests\unit\test_model_runtime.py` 检查。

### repair stages

| stage | 用途 |
| --- | --- |
| `targeted` | 精确字段修复，例如 ZIP EOCD、7z header CRC、RAR end block。 |
| `safe_repair` | 边界修剪、尾部垃圾、元数据降级、低风险部分恢复。 |
| `deep` | 高成本扫描或重建，例如 ZIP deep partial、nested payload、7z solid block salvage、RAR quarantine。 |

`stages.deep` 默认关闭，但 `auto_deep.enabled` 默认开启：只有 targeted/safe 失败、verification 仍请求 repair、且输入大小低于限制时，才自动尝试少量 deep 候选。

### beam

| 字段 | 说明 |
| --- | --- |
| `enabled` | 是否启用候选 beam 评估。 |
| `beam_width` | 每轮保留的状态数量。 |
| `max_candidates_per_state` | 每个状态最多展开候选数。 |
| `max_analyze_candidates` | 每轮进入 analysis 的候选上限。 |
| `max_assess_candidates` | 每轮进入 extraction/verification 的候选上限。 |
| `max_rounds` | 单次 beam 最多轮数。 |
| `min_improvement` | 候选必须超过 incumbent 的最小完整度提升。 |

候选比较会综合 assessment status、完整度、complete/partial/failed/missing 文件数、source integrity、patch cost 和 repair module 排名。完整度没有提升时，loop 会主动停止。

### 当前模块矩阵

配置文件中的 `repair.modules` 应与注册表一致。可以用下面的脚本检查：

```powershell
@'
from sunpack.repair.pipeline.registry import discover_repair_modules, get_repair_module_registry
discover_repair_modules()
print(sorted(get_repair_module_registry().all()))
'@ | python -
```

当前主要能力：

| 格式 | 能力 |
| --- | --- |
| ZIP | EOCD/comment/CD count/CD offset/ZIP64/local header/data descriptor 修复，central directory rebuild，entry quarantine，partial/deep recovery，overlap/duplicate/conflict resolver。 |
| TAR | header checksum、metadata downgrade、sparse/PAX/GNU longname、trailing junk、trailing zero block、压缩 TAR 截断恢复。 |
| gzip/bzip2/xz/zstd | trailing junk trim、footer/frame salvage、truncated partial recovery。 |
| 7z | start header CRC、next header field、boundary trim、precise boundary、CRC field、solid block partial salvage。 |
| RAR | trailing junk、carrier crop、block chain trim、end block repair、file quarantine rebuild。 |
| nested/carrier | carrier crop deep recovery、nested payload salvage。 |

旧键 `repair.trigger_on_medium_confidence`、`repair.trigger_on_extraction_failure` 和 `repair.thresholds` 已移除；配置中出现这些键会直接报错。

## detection

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | detection 层总开关。设为 `false` 时不执行 detection 规则，只对常规归档扩展名/分卷入口生成任务；需要完全绕过初始扫描时使用 `extract --direct-file <file>`。 |

## detection.fact_collectors

| 名称 | 作用 |
| --- | --- |
| `file_facts` | 采集路径、名称、父目录、大小等基础信息。 |
| `magic_bytes` | 读取文件头 magic bytes。 |
| `scene_markers` | 采集目录场景 marker，供 `scene_facts` 处理器使用。 |

## detection.processors

| 名称 | 作用 |
| --- | --- |
| `embedded_archive` | 对普通归档检测尚未解决且入选大小覆盖集的文件执行无扩展名嵌入归档深扫。 |
| `scene_facts` | 识别游戏、程序、资源目录等场景。 |
| `zip_structure` | 检查 ZIP local header。 |
| `zip_eocd_structure` | 检查 ZIP EOCD 和 central directory。 |
| `tar_header_structure` | 检查 TAR header checksum 和 ustar marker。 |
| `compression_stream_structure` | 检查 gzip、bzip2、xz、zstd 轻量流结构。 |
| `pe_overlay_structure` | 检查 PE overlay 中的归档载荷。 |
| `seven_zip_structure` | 检查 7z signature、start header CRC、next header 范围和 NID。 |
| `rar_structure` | 检查 RAR4/RAR5 signature、main header 和 block/header walk。 |

嵌入扫描只有一个成本字段，位于 `embedded_payload_identity` 规则：

| 字段 | 说明 |
| --- | --- |
| `deep_scan_single_candidate_ratio` | 单个未解决逻辑候选达到未解决候选总字节数的最低占比；默认 `0.3`。达到阈值的候选均执行可靠完整扫描。 |

单候选占比决定“哪些逻辑候选获准执行整个 embedded payload precheck 模块”，不限制单个候选的读取范围。未获准的候选不会解析 PE、识别安装器或扫描嵌入归档。分卷只作为一个逻辑候选参与总大小计算，成员卷不会重复计数。获准后先识别 executable carrier；命中已知安装器会立即拒绝且不启动完整嵌入扫描。嵌入扫描不检查扩展名，也没有窗口、最大命中数或扫描档位。一次 Rust 顺序读取同时查找所有支持格式；结构校验得到的命中图会传给 analysis，避免再次执行全流签名扫描。

## detection.rule_pipeline

检测器在初轮规则未接受候选时，还可调用结构分析器进行救援。初轮 `structure_evidence` 只处理具有归档扩展名、归档 magic、probe、PE overlay 或分卷关系等正向先验的候选，默认读取头尾各 64 KiB且不执行完整流扫描。完全未知的二进制文件由 `embedded_payload_identity` 的单候选占比策略选择后再执行完整流扫描，避免普通资源文件在初轮被逐字节读取。以下字段位于 `detection`：

| 字段 | 说明 |
| --- | --- |
| `content_structure_rescue_enabled` | 启用规则拒绝后的结构救援。 |
| `content_structure_rescue_full_scan_max_bytes` | 对不超过该大小且头尾未确认的候选扫描完整逻辑流；默认 64 MiB。 |
| `content_structure_rescue_deep_scan` | 对任意大小候选执行完整逻辑流扫描。会产生与文件总大小等量的最低 I/O，应仅在必须发现任意中间位置 embedding 时开启。 |

完整流扫描是发现“任意位置 embedding”的物理必要条件；默认预算避免对大量数 GiB 普通文件逐字节重读。超过预算的文件仍会进行头尾结构分析、ZIP 尾目录回链和分卷逻辑视图验证。

检测规则分两层：

- `precheck`：完整结构的严格识别。每个格式规则声明常见格式和扩展名；关系层提供逻辑分卷提示后，匹配规则会被临时提前，校验失败再回到配置顺序。安装器否决与 embedded payload 识别固定最后执行。
- `scoring`：只处理字段损坏、结构不完整等模糊证据。

每条规则至少包含：

```json
{"name": "zip_structure_accept", "enabled": true}
```

`config validate` 会校验规则名和规则 schema。默认配置的主要规则：

| 规则 | 层 | 说明 |
| --- | --- | --- |
| `zip_structure_accept` | precheck | 结构可信的 ZIP 快速接受。 |
| `tar_structure_accept` | precheck | 结构可信的 TAR 快速接受。 |
| `seven_zip_structure_accept` | precheck | start/next header 可信的 7z 快速接受。 |
| `rar_structure_accept` | precheck | main header/block walk 可信的 RAR 快速接受。 |
| `compression_stream_accept` | precheck | 完整校验 gzip、bzip2、xz、zstd 流并快速接受。 |
| `embedded_payload_identity` | precheck | 先否决已知安装器，再对获准深扫且找到可靠嵌入归档的文件直接接受。 |
| `zip_structure_identity` | scoring | ZIP local header、EOCD、CD walk 加分。 |
| `tar_structure_identity` | scoring | TAR header、ustar、entry walk 加分。 |
| `seven_zip_structure_identity` | scoring | 7z magic/header/NID 加分。 |
| `rar_structure_identity` | scoring | RAR magic/header/block walk 加分。 |
| `compression_stream_identity` | scoring | gzip、bzip2、xz、zstd 结构加分。 |

历史 `extension`、`magic_bytes`、`embedded_archive` scoring 规则已移出 active 规则包；CAB、ARJ、CPIO 的孤立检测支持以及 confirmation 层也已删除。当前主流水线由严格 precheck 和容损 scoring 消费结构 fact，由 precheck 最后的 `embedded_payload_identity` 统一执行安装器否决并消费 embedded 和 overlay 事实。安装器文件读取与特征匹配由 Rust 实现；命中后不会调度完整嵌入归档扫描。

### deep_scan_single_candidate_ratio

默认扫描普通检测尚未解决集合中，单个逻辑候选大小占该集合总大小至少 30% 的候选：

```json
{
  "detection": {
    "rule_pipeline": {
      "precheck": [
        {
          "name": "embedded_payload_identity",
          "deep_scan_single_candidate_ratio": 0.3
        }
      ]
    }
  }
}
```

`0` 禁用该阶段。阈值使用 `>=` 判断，所有达到阈值的候选都会扫描；默认 `0.3` 因而同一集合最多选中三个正大小候选。`1` 只会扫描独占未解决候选总大小的单个候选。例如只扫描占比至少 50% 的候选：

```json
{
  "name": "embedded_payload_identity",
  "enabled": true,
  "deep_scan_single_candidate_ratio": 0.5
}
```

## 密码文件

`builtin_passwords.txt` 是内置高频密码表，按每行一个密码读取。不存在时程序会尝试创建默认文件。

`passwords.clipboard_passwords_enabled` 控制普通 CLI 启动时是否读取当前剪贴板文本作为本次运行的密码来源。该开关不影响 watch 服务的剪贴板监控；watch 监控仍由 `watch.clipboard_monitor_enabled` 控制，并会把最近剪贴板密码合并进内置密码文件的托管区。

密码来源顺序：

1. `--password` 和 `--pw-file` 提供的用户密码。
2. 最近成功密码。
3. `builtin_passwords.txt` 内置密码。

使用 `--no-builtin-pw` 可禁用内置密码。

## 修改建议

- 想减少误解压：优先调 `filesystem.scan_filters`、结构 identity 和确认规则。
- 想提高召回率：优先调 `extension`、结构 identity、`embedded_payload_identity` 和阈值。
- 想控制修复成本：调 `repair.max_repair_*`、`deep`、`auto_deep` 和 `beam`。
- 想看为什么失败或为什么接受：跑 `inspect -v`，再看 recovery report 和 verification coverage。
- 修改后运行 `python sunpack.py config validate`。
