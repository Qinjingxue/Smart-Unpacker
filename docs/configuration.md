# 配置文件说明

主配置文件为 `sunpack_config.json`。源码运行时通常读取仓库根目录或当前工作目录中的配置；打包版本优先读取可执行文件旁边的外部配置，因此用户可以在不重新打包的情况下调整行为。

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

递归轮次只表示最多允许继续扫描多少轮。每轮完成后，coordinator 会用 `NestedOutputScanPolicy` 检查输出目录是否还值得扫描；强游戏/程序场景会被保护，避免把运行目录资源继续误当嵌套压缩包。

CLI 可用 `--recur` 临时覆盖。

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

扫描过滤器在目录遍历阶段执行，被过滤的条目不会进入 relation、detection 或 analysis。

`blacklist` 常用字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `patterns` | `list[str]` | 路径正则，命中后阻止扫描。 |
| `prune_dirs` | `list[str]` | 目录正则，命中后剪枝整个子树。 |
| `blocked_extensions` | `list[str]` | 阻止扫描的文件扩展名。 |

`size_minimum`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `min_inspection_size_bytes` | `int` | 小于该大小的文件不进入候选检测。 |

目录扫描使用 Rust `scan_directory_entries`。过滤器无法映射到 native 参数时会显性报错，不做 Python fallback。

## performance

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `scheduler_profile` | `str` | `auto`、`conservative` 或 `aggressive`。 |
| `max_extract_task_seconds` | `int` / `float` | 单个解压任务总时长上限，`0` 表示不限。 |
| `process_no_progress_timeout_seconds` | `int` / `float` | worker 无进展超时，`0` 表示不限。 |
| `process_sample_interval_ms` | `int` / `float` | worker 进程采样间隔。 |
| `persistent_workers` | `bool` | 是否复用 worker 进程。 |
| `profile_calibration_*` | 多种 | 并发调度 profile 的运行时反馈调节。 |
| `resource_guard` | `dict` | 可选资源护栏，用 analysis 估算的文件数、解包大小、压缩比等限制任务。 |

`auto` 会根据 CPU 和内存选择保守或激进档。配置文件中的超时会覆盖 profile 内置值。

`resource_guard` 当前常用字段：

| 字段 | 说明 |
| --- | --- |
| `enabled` | 是否启用资源护栏。 |
| `max_file_count` | 归档条目数超过该值时阻止解压，`0` 表示不限。 |
| `max_total_unpacked_size` | 估算总解包大小上限，字节，`0` 表示不限。 |
| `max_largest_item_size` | 单个最大条目上限，字节，`0` 表示不限。 |
| `max_compression_ratio` | 压缩比上限，`0` 表示不限。 |

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
| `modules` | `list[dict]` | 显式 repair 模块开关。 |

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

## detection.fact_collectors

| 名称 | 作用 |
| --- | --- |
| `file_facts` | 采集路径、名称、父目录、大小等基础信息。 |
| `magic_bytes` | 读取文件头 magic bytes。 |
| `scene_markers` | 采集目录场景 marker，供 `scene_facts` 处理器使用。 |

## detection.processors

| 名称 | 作用 |
| --- | --- |
| `embedded_archive` | 扫描图片、PDF、GIF、WebP 或可疑资源文件中的嵌入式归档。 |
| `scene_facts` | 识别游戏、程序、资源目录等场景。 |
| `seven_zip_probe` | 生成 7z.dll 轻量 probe 结果。 |
| `seven_zip_validation` | 生成 7z.dll test 结果。 |
| `zip_structure` | 检查 ZIP local header。 |
| `zip_eocd_structure` | 检查 ZIP EOCD 和 central directory。 |
| `tar_header_structure` | 检查 TAR header checksum 和 ustar marker。 |
| `compression_stream_structure` | 检查 gzip、bzip2、xz、zstd 轻量流结构。 |
| `archive_container_structure` | 检查 CAB、ARJ、CPIO 等轻量容器结构。 |
| `pe_overlay_structure` | 检查 PE overlay 中的归档载荷。 |
| `seven_zip_structure` | 检查 7z signature、start header CRC、next header 范围和 NID。 |
| `rar_structure` | 检查 RAR4/RAR5 signature、main header 和 block/header walk。 |

嵌入扫描常用字段：

| 字段 | 说明 |
| --- | --- |
| `carrier_exts` | 可能携带尾部归档载荷的扩展名。 |
| `ambiguous_resource_exts` | 需要宽松扫描的可疑资源扩展名。 |
| `loose_scan_min_prefix` | 宽松扫描时要求归档头前至少有多少字节。 |
| `loose_scan_min_tail_bytes` | 宽松扫描时要求候选尾部至少有多少字节。 |
| `loose_scan_max_hits` | 宽松扫描最多接受的命中数量。 |
| `loose_scan_tail_window_bytes` | 优先扫描的尾部窗口大小。 |
| `loose_scan_full_scan_max_bytes` | 小于该大小时允许全文件扫描。 |
| `loose_scan_deep_scan` | 是否启用更深入的宽松扫描。 |
| `carrier_scan_tail_window_bytes` | 载体尾部扫描窗口大小。 |
| `carrier_scan_prefix_window_bytes` | 载体头部前缀扫描窗口大小。 |
| `carrier_scan_full_scan_max_bytes` | 载体全文件扫描上限，`0` 表示默认禁用。 |
| `carrier_scan_deep_scan` | 是否启用更深入的载体扫描。 |

## detection.rule_pipeline

检测规则分三层：

- `precheck`：强场景保护、高置信结构快速接受。
- `scoring`：扩展名、真实结构、embedded payload、场景扣分。
- `confirmation`：7z.dll probe/test 等确认层。

每条规则至少包含：

```json
{"name": "extension", "enabled": true}
```

`config validate` 会校验规则名和规则 schema。默认配置的主要规则：

| 规则 | 层 | 说明 |
| --- | --- | --- |
| `scene_protect` | precheck | 保护强游戏/程序/资源场景。 |
| `zip_structure_accept` | precheck | 结构可信的 ZIP 快速接受。 |
| `tar_structure_accept` | precheck | 结构可信的 TAR 快速接受。 |
| `seven_zip_structure_accept` | precheck | start/next header 可信的 7z 快速接受。 |
| `rar_structure_accept` | precheck | main header/block walk 可信的 RAR 快速接受。 |
| `extension` | scoring | 扩展名加分。 |
| `embedded_payload_identity` | scoring | carrier、loose scan、PE overlay 归档载荷加分。 |
| `zip_structure_identity` | scoring | ZIP local header、EOCD、CD walk 加分。 |
| `tar_structure_identity` | scoring | TAR header、ustar、entry walk 加分。 |
| `seven_zip_structure_identity` | scoring | 7z magic/header/NID 加分。 |
| `rar_structure_identity` | scoring | RAR magic/header/block walk 加分。 |
| `archive_container_identity` | scoring | CAB、ARJ、CPIO 等容器加分。 |
| `compression_stream_identity` | scoring | gzip、bzip2、xz、zstd 结构加分。 |
| `scene_penalty` | scoring | 对资源文件、运行目录、弱保护路径扣分。 |
| `seven_zip_probe` | confirmation | 用 7z.dll probe 确认中间分候选。 |
| `seven_zip_validation` | confirmation | 用 7z.dll test 确认中间分候选。 |

历史 `magic_bytes`、`embedded_archive` scoring 规则已移出 active 规则包；当前主流水线由格式结构规则消费 magic/结构 fact，由 `embedded_payload_identity` 统一消费 embedded 和 overlay 事实。

## 密码文件

`builtin_passwords.txt` 是内置高频密码表，按每行一个密码读取。不存在时程序会尝试创建默认文件。

密码来源顺序：

1. `--password` 和 `--pw-file` 提供的用户密码。
2. 最近成功密码。
3. `builtin_passwords.txt` 内置密码。

使用 `--no-builtin-pw` 可禁用内置密码。

## 修改建议

- 想减少误解压：优先调 `filesystem.scan_filters`、`scene_protect`、`scene_penalty`。
- 想提高召回率：优先调 `extension`、结构 identity、`embedded_payload_identity` 和阈值。
- 想控制修复成本：调 `repair.max_repair_*`、`deep`、`auto_deep` 和 `beam`。
- 想看为什么失败或为什么接受：跑 `inspect -v`，再看 recovery report 和 verification coverage。
- 修改后运行 `python sunpack.py config validate`。
