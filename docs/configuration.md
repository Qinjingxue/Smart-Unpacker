# 配置文件说明

主配置文件为 `smart_unpacker_config.json`。程序启动时会从资源根查找该文件；打包版本优先读取可执行文件旁边的配置，源码运行时通常读取仓库根目录或当前工作目录中的配置。

快速检查配置：

```powershell
python sunpack_cli.py config validate
```

查看当前配置：

```powershell
python sunpack_cli.py config show
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
  "verification": {},
  "repair": {},
  "detection": {}
}
```

## cli

```json
{
  "cli": {
    "language": "zh"
  }
}
```

字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `language` | `str` | CLI 语言。`zh` 启用中文，其它值回退英文。 |

## thresholds

```json
{
  "thresholds": {
    "archive_score_threshold": 6,
    "maybe_archive_threshold": 3
  }
}
```

字段：

| 字段 | 类型 | 默认行为 | 说明 |
| --- | --- | --- | --- |
| `archive_score_threshold` | `int` | 6 | 分数达到该值时判定为压缩包。 |
| `maybe_archive_threshold` | `int` | 3 | 分数达到该值但未达压缩包阈值时进入可疑区间。 |

确认层处理 `maybe_archive_threshold <= score < archive_score_threshold` 的中间可疑区间。因为分数是整数，确认层上限等价于 `archive_score_threshold - 1`。

## recursive_extract

```json
{
  "recursive_extract": "*"
}
```

取值：

| 值 | 说明 |
| --- | --- |
| `*` | 无限递归。 |
| 正整数 | 固定递归轮数。 |
| `?` | 每轮递归后询问是否继续。 |

CLI 可用 `--recur` 临时覆盖：正整数表示固定轮数，`*` 表示无限递归，`?` 表示提示模式。

递归轮次只表示最多允许继续扫描多少轮。每轮解压完成后，coordinator 会调用 `detection.NestedOutputScanPolicy` 检查输出目录是否还包含值得检测的候选；如果输出目录已经呈现强游戏/程序场景，则会跳过该目录，避免把运行目录资源继续误当作嵌套压缩包。

## post_extract

```json
{
  "post_extract": {
    "archive_cleanup_mode": "r",
    "flatten_single_directory": true
  }
}
```

字段：

| 字段 | 类型 | 可选值 | 说明 |
| --- | --- | --- | --- |
| `archive_cleanup_mode` | `str` | `d`、`r`、`k` | 成功解压后如何处理原压缩包：`d` 删除，`r` 回收站，`k` 不动。 |
| `flatten_single_directory` | `bool` | `true`、`false` | 解压结果只有一个顶层目录时，是否把其内容提升一层。 |

建议优先使用 `r`。`d` 会直接删除成功解压的原压缩包。

## performance

```json
{
  "performance": {
    "scheduler_profile": "auto",
    "max_extract_task_seconds": 1800,
    "process_no_progress_timeout_seconds": 180
  }
}
```

字段：

| 字段 | 类型 | 可选值 | 说明 |
| --- | --- | --- | --- |
| `scheduler_profile` | `str` | `auto`、`conservative`、`aggressive` | 并发调度档位。 |
| `max_extract_task_seconds` | `int` / `float` | `>= 0` | 单个解压进程允许运行的最长秒数。`0` 表示不限制。 |
| `process_no_progress_timeout_seconds` | `int` / `float` | `>= 0` | 解压进程没有输出或进展采样时允许等待的秒数。`0` 表示不限制。 |

`auto` 会根据 CPU 核心数和内存选择保守或激进档。`conservative` 初始并发较低，更适合机械硬盘或后台运行；`aggressive` 初始并发较高，更适合多核和高速 SSD。

`max_extract_task_seconds` 和 `process_no_progress_timeout_seconds` 会随 `performance` 配置传给单归档解压器和批量调度器。当前默认配置使用 `1800` 秒总时长限制和 `180` 秒无进展限制；调度档位内置值为 `0`，表示如果配置文件不覆盖则不启用这两个超时。

## verification

```json
{
  "verification": {
    "enabled": true,
    "initial_score": 100,
    "pass_threshold": 70,
    "fail_fast_threshold": 40,
    "max_retries": 2,
    "cleanup_failed_output": true,
    "methods": [
      {"name": "extraction_exit_signal", "enabled": true},
      {"name": "output_presence", "enabled": true},
      {"name": "expected_name_presence", "enabled": true},
      {"name": "manifest_size_match", "enabled": true},
      {"name": "archive_test_crc", "enabled": false},
      {"name": "sample_readability", "enabled": false}
    ]
  }
}
```

字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `enabled` | `bool` | 是否启用解压结果校验流水线。 |
| `initial_score` | `int` | 校验初始分。 |
| `pass_threshold` | `int` | 校验完成后的通过阈值。 |
| `fail_fast_threshold` | `int` | 每个 method 执行后都会检查；低于该值立即失败。 |
| `max_retries` | `int` | 校验失败后的重新解压次数。`0` 表示不重试，`1` 表示额外重试一次。 |
| `cleanup_failed_output` | `bool` | 校验失败且需要重试时，是否先删除本次输出目录。 |
| `methods` | `list[dict]` | 有序校验方法列表，顺序即执行顺序。 |

如果配置中省略整个 `verification` 段，代码默认不会启用校验流水线。仓库自带的 `smart_unpacker_config.json` 已显式启用校验，并关闭成本较高或依赖额外 native 能力的 CRC / 抽样可读性方法。

`methods` 每项至少包含：

```json
{"name": "method_name", "enabled": true}
```

内置低成本校验方法：

| 方法 | 说明 |
| ---- | ---- |
| `extraction_exit_signal` | 检查解压返回值，解压失败直接校验失败。 |
| `output_presence` | 检查输出目录是否存在、是否为空、是否只有临时文件。 |
| `expected_name_presence` | 如果已有归档条目名样本，检查这些名字是否出现在输出目录中。缺少样本时跳过。 |
| `manifest_size_match` | 如果已有 resource analysis，对比归档内文件数/原始大小和实际输出。缺少 manifest 时跳过。 |
| `archive_test_crc` | 通过 C++ wrapper 读取归档 CRC manifest 并测试归档；通过 Rust 计算输出文件 CRC 后对比。后端不可用或归档无 CRC 时跳过。 |
| `sample_readability` | 通过 Rust 抽样打开并读取输出文件头尾，确认产物基本可读。 |

## repair

```json
{
  "repair": {
    "enabled": true,
    "stages": {
      "targeted": true,
      "safe_repair": true,
      "deep": false
    },
    "safety": {
      "allow_unsafe": false,
      "allow_partial": true,
      "allow_lossy": false
    },
    "deep": {
      "max_candidates_per_module": 3,
      "max_seconds_per_module": 30,
      "max_input_size_mb": 512,
      "verify_candidates": true
    }
  }
}
```

字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `enabled` | `bool` | 是否启用损坏结构修复流水线。 |
| `max_modules_per_job` | `int` | 单个修复任务最多尝试多少个匹配模块。 |
| `max_attempts_per_task` | `int` | 单个归档任务最多执行多少轮修复。 |
| `trigger_on_medium_confidence` | `bool` | analysis 给出中等置信度损坏候选时，是否在解压前尝试修复。 |
| `trigger_on_extraction_failure` | `bool` | 解压失败后是否尝试修复并重试。 |
| `stages.targeted` | `bool` | 是否允许精确结构修复模块。 |
| `stages.safe_repair` | `bool` | 是否允许低风险边界/部分恢复模块。 |
| `stages.deep` | `bool` | 是否允许高成本深度修复模块；默认关闭。 |
| `safety.allow_unsafe` | `bool` | 是否允许运行声明为非安全的修复模块。 |
| `safety.allow_partial` | `bool` | 是否允许产出 partial 结果的模块，例如只恢复可读条目的 ZIP 候选。 |
| `safety.allow_lossy` | `bool` | 是否允许声明为有损的修复模块；默认关闭。 |
| `deep.max_candidates_per_module` | `int` | deep 模块单次最多生成/验证的候选数量。 |
| `deep.max_seconds_per_module` | `int` / `float` | deep 模块单次预算秒数，`0` 表示不限制。 |
| `deep.max_input_size_mb` | `int` / `float` | deep 模块可处理的输入大小上限，`0` 表示不限制。 |
| `deep.verify_candidates` | `bool` | deep 模块是否应在返回前验证候选。 |

`repair` 只在 analysis/extraction 阶段之后介入，不参与 detection 的大规模脏数据初筛。新增高成本模块时应声明 `stage="deep"`，并根据行为设置 `safe`、`partial`、`lossy` 元数据，让调度器用上面的安全门过滤。

## detection.fact_collectors

```json
{
  "detection": {
    "fact_collectors": [
      {"name": "file_facts", "enabled": true},
      {"name": "magic_bytes", "enabled": true},
      {"name": "scene_markers", "enabled": true}
    ]
  }
}
```

当前配置中该段用于记录采集器模块开关。核心调度仍以规则声明的 facts 为准。

常见采集器：

| 名称 | 作用 |
| --- | --- |
| `file_facts` | 采集文件路径、名称、父目录和大小。 |
| `magic_bytes` | 读取文件开头魔数字节。 |
| `scene_markers` | 基于目录扫描结果采集场景 marker，供 `scene_facts` 处理器生成高级场景 facts。 |

## detection.processors

```json
{
  "detection": {
    "processors": [
      {
        "name": "embedded_archive",
        "enabled": true,
        "carrier_exts": [".jpg", ".jpeg", ".png", ".pdf", ".gif", ".webp"],
        "ambiguous_resource_exts": [".dat", ".bin"],
        "loose_scan_min_tail_bytes": 4096
      }
    ]
  }
}
```

常见处理器：

| 名称 | 作用 |
| --- | --- |
| `embedded_archive` | 扫描图片、PDF、GIF、WebP 或可疑资源文件中的嵌入式压缩包。 |
| `scene_facts` | 识别游戏、程序等目录场景。 |
| `seven_zip_probe` | 生成 7-Zip 轻量探测结果。 |
| `seven_zip_validation` | 生成 7-Zip 测试结果。 |
| `zip_structure` | 检查 ZIP 局部文件头可信度。 |
| `zip_eocd_structure` | 检查 ZIP EOCD 和 central directory 结构。 |
| `tar_header_structure` | 检查 TAR header checksum 和 ustar marker。 |
| `compression_stream_structure` | 检查 gzip、bzip2、xz、zstd 的轻量流结构。 |
| `archive_container_structure` | 检查 CAB、ARJ、CPIO 的轻量容器结构。 |
| `seven_zip_structure` | 检查 7z signature、版本、start header CRC 和 next header 范围。 |
| `rar_structure` | 检查 RAR4/RAR5 signature 与首个 header 结构。 |

处理器配置会作为 fact 配置传入对应逻辑。嵌入扫描相关字段常见含义：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `carrier_exts` | `list[str]` | 可能携带尾部压缩包载荷的文件扩展名。 |
| `ambiguous_resource_exts` | `list[str]` | 需要宽松扫描的可疑资源扩展名。 |
| `loose_scan_min_prefix` | `int` | 宽松扫描时要求压缩包头前至少有多少字节。 |
| `loose_scan_min_tail_bytes` | `int` | 宽松扫描时要求候选尾部至少有多少字节。 |
| `loose_scan_max_hits` | `int` | 宽松扫描最多接受的命中数量。 |
| `loose_scan_tail_window_bytes` | `int` | 优先扫描的尾部窗口大小。 |
| `loose_scan_full_scan_max_bytes` | `int` | 小于该大小时允许全文件扫描。 |
| `loose_scan_deep_scan` | `bool` | 是否启用更深入的宽松扫描。 |
| `carrier_scan_tail_window_bytes` | `int` | 载体尾部扫描窗口大小。 |
| `carrier_scan_prefix_window_bytes` | `int` | 载体头部前缀扫描窗口大小，用于识别靠近文件开头的 `JPG + RAR/7z/ZIP` 伪装载荷。 |
| `carrier_scan_full_scan_max_bytes` | `int` | 载体全文件扫描上限。`0` 表示默认禁用全文件扫描，只扫尾部窗口。 |
| `carrier_scan_deep_scan` | `bool` | 是否启用更深入的载体扫描。开启后即使超过上限也允许全文件扫描。 |

## filesystem.directory_scan_mode

控制扫描目标目录时是否进入已有子目录。它只影响目录扫描范围，不影响解压后是否继续进入下一轮递归解压；后者由 `recursive_extract` 控制。

| 值 | 说明 |
| --- | --- |
| `*` | 默认行为。扫描目标目录以及全部子目录。 |
| `-` | 只扫描目标目录第一层文件，不进入子目录。 |

示例：

```json
{
  "filesystem": {
    "directory_scan_mode": "-"
  }
}
```

## filesystem.scan_filters

扫描过滤器在目录遍历阶段执行，输出仍是 `FileEntry` / `DirectorySnapshot`。过滤器按渐进式元数据阶段运行：先使用 path/kind，再按需使用 size、mtime 等字段。被过滤的条目不会进入 relation 或 detection。

```json
{
  "filesystem": {
    "directory_scan_mode": "*",
    "scan_filters": [
      {"name": "blacklist", "enabled": true},
      {"name": "size_minimum", "enabled": true}
    ]
  }
}
```

`blacklist`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `patterns` | `list[str]` | 路径正则，命中后阻止扫描。命中目录时会剪枝整个子树。 |
| `prune_dirs` | `list[str]` | 目录正则，仅对目录生效；命中后剪枝整个子树，不会过滤同名文件。适合跳过 `node_modules`、`site-packages`、缓存目录等。 |
| `blocked_extensions` | `list[str]` | 阻止扫描的文件扩展名列表。 |

默认配置会剪枝 `.git`、`.venv`、`node_modules`、`site-packages` 等目录，并阻止 `.dll`、`.json`、`.pak`、`.jar`、`.apk`、Office Open XML、模型权重等常见资源或容器扩展名进入检测。若需要提高召回率，先在这里放开对应扩展名，再配合 `inspect -v` 观察 detection 打分。

`size_minimum`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `min_inspection_size_bytes` | `int` | 小于该大小的文件不进入候选检测。 |

默认值为 `1048576`，也就是小于 1 MiB 的文件不进入候选检测。

目录扫描使用 `smart_unpacker_native.scan_directory_entries`，并要求扫描过滤器保持为原生层支持的内置 `blacklist` / `size_minimum` 组合。原生扩展缺失、调用失败或过滤器无法映射到原生参数时会显性报错。

## detection.rule_pipeline

检测规则分三层：

```json
{
  "detection": {
    "rule_pipeline": {
      "precheck": [],
      "scoring": [],
      "confirmation": []
    }
  }
}
```

每条规则至少包含：

```json
{"name": "extension", "enabled": true}
```

`name` 必须是已注册规则名，`enabled` 表示是否启用。其它字段必须由该规则的 schema 声明，否则 `config validate` 会报错。

### precheck

`scene_protect`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `scene_rules` | `list[dict]` | 场景识别规则。 |
| `protect_weak_matches` | `bool` | 是否保护弱匹配场景。 |
| `scene_context_max_parent_depth` | `int` | 向上查找场景根目录的最大层数。 |

`zip_structure_accept`：

该规则只会在 `file.magic_bytes` 命中 ZIP 起始魔数（`PK\x03\x04`、`PK\x05\x06`、`PK\x07\x08`）后收集 `zip.eocd_structure`，避免对非 ZIP 候选做尾部 EOCD 扫描。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `accept_empty_zip` | `bool` | 是否允许结构合法的空 ZIP 在 precheck 阶段直接接受。 |
| `max_cd_entries_to_walk` | `int` | precheck 阶段最多检查多少个 central directory entry 及其 local header 回指。 |

`tar_structure_accept`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `max_entries_to_walk` | `int` | precheck 阶段最多检查多少个 TAR entry。 |

`seven_zip_structure_accept`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `max_next_header_check_bytes` | `int` | precheck 阶段最多读取多少 7z next header 字节来校验 CRC 和首个 NID。 |

`rar_structure_accept`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `max_first_header_check_bytes` | `int` | precheck 阶段最多读取多少 RAR header 字节来校验 main header CRC 和后续 block/header。 |

### scoring

`extension`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `extension_score_groups` | `list[dict]` | 扩展名分组，每组通常包含 `score` 和 `extensions`。 |

`embedded_payload_identity`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `carrier_tail_score` | `int` | 载体尾部嵌入命中时的分数。 |
| `loose_scan_score` | `int` | 宽松扫描命中时的分数。 |
| `overlay_start_score` | `int` | PE overlay 起点处存在归档载荷时的分数。 |
| `overlay_near_start_score` | `int` | PE overlay 起点附近存在归档载荷时的分数。 |
| `zip_plausibility_required_for_loose_scan` | `bool` | 宽松扫描命中 ZIP 时，是否要求 ZIP local header 结构可信。 |
| `zip_plausibility_required_for_carrier_tail` | `bool` | 载体尾部命中 ZIP 时，是否要求 ZIP local header 结构可信。 |
| 其它嵌入扫描字段 | 多种 | 与 `embedded_archive` 处理器同名字段含义一致。 |

`seven_zip_structure_identity`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `magic_score` | `int` | 7z 起始魔数命中但 start header 证据不足时的弱分。 |
| `structure_score` | `int` | 7z start header CRC 和 next header 范围可信时的分数。 |
| `next_header_nid_score` | `int` | 7z next header CRC 与首个 NID 都可信时的分数。 |

`rar_structure_identity`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `magic_score` | `int` | RAR 起始魔数命中但 first header 证据不足时的弱分。 |
| `structure_score` | `int` | RAR4/RAR5 首个 header 结构可信时的分数。 |
| `block_walk_score` | `int` | RAR main header 后的第二个 block/header 可遍历且 CRC 可信时的分数。 |

`zip_structure_identity`：

`zip.local_header` 始终按需收集；`zip.eocd_structure` 只在文件起始魔数命中 ZIP 相关签名后收集。前置 stub、overlay 或普通载体内嵌 ZIP 的识别应由 `embedded_payload_identity` 负责。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `magic_score` | `int` | ZIP-like 起始魔数命中但结构证据不足时的弱分。 |
| `local_header_score` | `int` | ZIP local file header 可信但 EOCD/CD 证据不足时的分数。 |
| `eocd_score` | `int` | ZIP EOCD 和 central directory 结构可信时的分数。 |
| `cd_walk_score` | `int` | central directory entry 可遍历且能回指 local header 时的分数。 |
| `embedded_eocd_score` | `int` | ZIP 结构前存在 stub 或前置载荷时的分数。 |
| `empty_eocd_score` | `int` | 空 ZIP EOCD 结构可信时的分数。 |
| `max_cd_entries_to_walk` | `int` | 最多检查多少个 central directory entry 及其 local header 回指。 |

`tar_structure_identity`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `tar_header_score` | `int` | TAR header checksum 可信时的分数。 |
| `ustar_header_score` | `int` | ustar marker 与 checksum 都可信时的分数。 |
| `entry_walk_score` | `int` | TAR entry walk 成功时的分数。 |
| `max_entries_to_walk` | `int` | 最多检查多少个 TAR entry。 |

`archive_container_identity`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `container_score` | `int` | CAB、ARJ、CPIO 轻量容器结构可信时的分数。 |

`compression_stream_identity`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `magic_score` | `int` | gzip、bzip2、xz、zstd 起始魔数命中但结构证据不足时的弱分。 |
| `stream_score` | `int` | gzip、bzip2、xz、zstd 轻量流结构可信时的分数。 |

`scene_penalty`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `scene_rules` | `list[dict]` | 场景识别规则。 |
| `runtime_resource_archive_penalty` | `int` | 运行目录资源归档扣分。 |
| `weak_protected_path_penalty` | `int` | 弱保护路径扣分。 |
| `resource_penalty` | `int` | 常见资源文件扣分。 |
| `runtime_exact_path_penalty` | `int` | 运行时精确路径扣分。 |
| `semantic_resource_exts` | `list[str]` | 语义上更像资源或程序文件的扩展名。 |
| `likely_resource_exts` | `list[str]` | 常见媒体、文本、文档等资源扩展名。 |
| `scene_context_max_parent_depth` | `int` | 向上查找场景根目录的最大层数。 |

历史 `magic_bytes`、`embedded_archive` scoring 规则已移出 active 规则包；当前主流水线由各格式结构规则消费起始魔数/结构 fact，由 `embedded_payload_identity` 统一消费 `embedded_archive.analysis` 和 `pe.overlay_structure`。

### confirmation

`seven_zip_probe`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `score_min` | `int` | 可选高级项，覆盖该规则的最低触发分数。 |
| `score_max` | `int` | 可选高级项，覆盖该规则的最高触发分数。 |
| `reject_executable_container` | `bool` | 是否拒绝 7-Zip 判断为可执行容器的文件。 |
| `reject_clear_non_archive` | `bool` | 是否拒绝明确不是归档的探测结果。 |

`seven_zip_validation`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `score_min` | `int` | 可选高级项，覆盖该规则的最低触发分数。 |
| `score_max` | `int` | 可选高级项，覆盖该规则的最高触发分数。 |
| `reject_on_failed` | `bool` | 7-Zip 测试失败时是否拒绝候选。 |

## 密码文件

`builtin_passwords.txt` 是内置高频密码表，按每行一个密码读取。不存在时程序会尝试创建默认文件，默认值包括 `123456`、`123`、`0000`、`789`。

运行时密码来源顺序：

1. `--password` 和 `--pw-file` 提供的用户密码。
2. 最近成功密码。
3. `builtin_passwords.txt` 内置密码。

使用 `--no-builtin-pw` 可禁用第 3 类。

## 修改建议

- 先用 `scan` 或 `inspect` 观察误判原因，再调整规则。
- 想减少误解压资源文件，优先调整 `filesystem.scan_filters` 中的 `blacklist`，以及 detection 的 `scene_protect`、`scene_penalty`。
- 想提高召回率，优先调整 `extension`、结构类 identity 规则、`embedded_payload_identity` 和阈值。
- 修改后运行 `python sunpack_cli.py config validate`。
