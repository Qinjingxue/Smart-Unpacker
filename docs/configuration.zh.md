# Smart Unpacker 配置文件详解

主配置文件是项目根目录或发布目录中的 `smart_unpacker_config.json`。这个文件必须是合法 JSON，不能写注释。路径类配置建议尽量使用正斜杠 `/`，例如 `FBX/weapon`，这样不需要转义。反斜杠写法仍然兼容，但 JSON 字符串里的反斜杠需要转义，例如正则 `FBX\weapon` 在 JSON 中应写成 `"FBX\\\\weapon"`。

当前配置不兼容早期的 `basic`、`advanced`、`detection` 顶层结构。程序只读取以下四个顶层配置块：

- `extraction_rules`：控制哪些文件会被识别、检查、跳过或保护。
- `post_extract`：控制成功解压后的原归档文件和目录整理行为。
- `recursive_extract`：控制递归解压轮数或交互模式。
- `performance`：控制并发调度和嵌入式归档扫描成本。

如果配置文件缺失，程序会自动生成推荐配置。如果某个标量值类型错误或取值非法，程序会回退到安全默认值。如果 `extensions`、`scene_rules`、`blacklist` 这类规则块缺失或格式非法，对应规则会按空配置处理。

## 顶层结构

```json
{
  "extraction_rules": {},
  "post_extract": {},
  "recursive_extract": "*",
  "performance": {}
}
```

## `extraction_rules`

`extraction_rules` 是最重要的配置块，决定“一个文件是否应该进入归档识别和解压流程”。

推荐顺序如下：

```json
{
  "extraction_rules": {
    "min_inspection_size_bytes": 1048576,
    "thresholds": {
      "archive_score_threshold": 6,
      "maybe_archive_threshold": 3
    },
    "extensions": {},
    "blacklist": {},
    "scene_rules": []
  }
}
```

### `extraction_rules.min_inspection_size_bytes`

类型：非负整数。

默认值：`1048576`，即 `1 MB`。

含义：小于该值的文件会跳过后续归档检查，直接判定为非归档。

常见调整：

- 设置为 `1048576`：默认保守策略，避免扫描大量小资源文件。
- 设置为 `0`：所有大小的文件都会进入检测，适合测试或处理很小的压缩包。
- 设置为更大的值：减少扫描成本，但可能漏掉小压缩包。

风险：调低会增加检查量和误判机会；调高会增加漏判机会。

### `extraction_rules.thresholds`

`thresholds` 控制评分系统的最终判定。程序会根据扩展名、魔数、分卷特征、7-Zip 探测结果、目录语义等信息给候选文件加分或减分。

```json
{
  "thresholds": {
    "archive_score_threshold": 6,
    "maybe_archive_threshold": 3
  }
}
```

#### `archive_score_threshold`

类型：正整数。

默认值：`6`。

含义：文件分数达到该值时，判定为 `archive`，会参与解压任务。

调参建议：

- 降低到 `4` 或 `5`：更激进，更容易解出伪装包，但误解压风险更高。
- 提高到 `7` 或更高：更保守，适合资源目录复杂、误判成本较高的场景。

#### `maybe_archive_threshold`

类型：非负整数。

默认值：`3`。

含义：文件分数达到该值但未达到 `archive_score_threshold` 时，判定为 `maybe_archive`。单文件 `maybe_archive` 通常不会直接解压，但在分卷组、组合关系或后续校验中可能参与判断。

调参建议：

- 降低：更容易把可疑文件保留为候选。
- 提高：减少可疑候选数量。

## `extraction_rules.extensions`

`extensions` 控制后缀层面的白名单、黑名单和资源保护。

重要规则：如果 `extensions` 缺失或不是对象，所有后缀集合都为空，不会自动使用内置后缀默认值。仓库自带配置文件中提供了一组推荐值。

```json
{
  "extensions": {
    "standard_archive_exts": [".7z", ".rar", ".zip", ".gz", ".bz2", ".xz"],
    "strict_semantic_skip_exts": [".dll", ".json", ".pak", ".unitypackage", ".docx", ".xlsx"],
    "ambiguous_resource_exts": [".dat", ".bin"],
    "likely_resource_exts_extra": [".jpg", ".png", ".mp3", ".mp4", ".txt", ".pdf"],
    "carrier_exts": [".jpg", ".jpeg", ".png", ".pdf", ".gif", ".webp"]
  }
}
```

所有后缀都建议写成带点的小写形式，例如 `.zip`。程序读取时会自动转小写，并会给不带点的值补点，例如 `"zip"` 会变成 `.zip`。

### `standard_archive_exts`

类型：字符串数组。

默认行为：缺失时为空。

含义：标准归档后缀白名单。命中后会增加归档评分，并在部分流程中优先作为扫描候选。

推荐值：

```json
[".7z", ".rar", ".zip", ".gz", ".bz2", ".xz"]
```

常见扩展：

```json
[".7z", ".rar", ".zip", ".gz", ".bz2", ".xz", ".cbz", ".cbr"]
```

风险：把应用包、资源包或文档后缀加入该列表，会明显增加误解压风险。

### `strict_semantic_skip_exts`

类型：字符串数组。

默认行为：缺失时为空。

含义：强语义保护后缀黑名单。命中这些后缀的文件，即使文件头看起来像归档，也默认不作为通用压缩包处理，除非它明确属于分卷相关场景。

推荐放入：

- 程序和系统文件：`.dll`、`.sys`、`.exe` 通常不建议直接加入，当前代码对独立 `.exe` 有额外保护，但自解压包仍可能需要被识别。
- 配置和数据文件：`.json`、`.xml`、`.ini`、`.db`。
- 游戏或应用资源包：`.pak`、`.obb`、`.unitypackage`。
- 本质是 ZIP 但通常不应作为普通压缩包解压的语义容器：`.jar`、`.apk`、`.ipa`、`.epub`、`.odt`、`.ods`、`.odp`、`.docx`、`.xlsx`、`.pptx`、`.whl`、`.xpi`、`.war`、`.ear`、`.aab`。

风险：加入太多会漏掉真实伪装包；加入太少会增加误解压资源文件的风险。

### `ambiguous_resource_exts`

类型：字符串数组。

默认行为：缺失时为空。

含义：易混淆资源后缀。命中后会轻微降低归档评分，但如果文件名、魔数、7-Zip 探测或嵌入式扫描给出强信号，仍可能被识别为归档。

推荐值：

```json
[".dat", ".bin"]
```

适用场景：很多游戏和应用会用 `.dat`、`.bin` 存放资源，同时真实压缩包也可能伪装成这些后缀。

### `likely_resource_exts_extra`

类型：字符串数组。

默认行为：缺失时为空。

含义：普通资源后缀列表。程序会把它和 `strict_semantic_skip_exts` 合并为“很可能是资源”的集合，用于减少不必要的 7-Zip 深度探测。

推荐放入：

- 图片：`.jpg`、`.jpeg`、`.png`、`.gif`、`.bmp`、`.webp`、`.tga`
- 音频：`.mp3`、`.wav`、`.ogg`、`.flac`、`.aac`
- 视频：`.mp4`、`.mkv`、`.avi`、`.mov`、`.wmv`、`.webm`
- 文本和文档：`.txt`、`.log`、`.csv`、`.pdf`

注意：如果这些后缀也出现在 `carrier_exts` 中，程序仍可针对“图片/PDF 后面拼接压缩包”的伪装形式做嵌入式扫描。

### `carrier_exts`

类型：字符串数组。

默认行为：缺失时为空。

含义：载体文件后缀。命中这些后缀时，程序会尝试检查文件尾部或文件内部是否拼接了 7z/RAR/ZIP 等归档数据。

推荐值：

```json
[".jpg", ".jpeg", ".png", ".pdf", ".gif", ".webp"]
```

风险：载体扫描会增加 I/O 成本。不要把大量普通资源后缀都加入这里，除非确实需要查找嵌入式压缩包。

## `extraction_rules.blacklist`

`blacklist` 是用户显式排除规则。命中的目录或文件不会参与后续扫描、重命名和解压。

```json
{
  "blacklist": {
    "directory_patterns": [
      "weapon",
      "FBX/weapon",
      ".*/weapon"
    ],
    "filename_patterns": [
      "readme\\.zip",
      ".*\\.unitypackage",
      "FBX/weapon/do_not_unpack\\.7z"
    ]
  }
}
```

通用规则：

- 类型必须是对象。
- `directory_patterns` 和 `filename_patterns` 必须是字符串数组。
- 每个字符串都会按 Python 正则表达式编译。
- 正则统一大小写不敏感。
- 非法正则会被忽略，不会中断程序。
- 匹配使用 `re.search`，不是全字符串匹配。需要精确匹配时请写 `^...$`。
- 匹配前会同时生成 Windows 风格和正斜杠风格的相对路径，例如 `FBX\weapon\demo.zip` 和 `FBX/weapon/demo.zip` 都可以命中。
- 推荐在配置中使用正斜杠 `/`，例如 `FBX/weapon`、`.*/weapon`、`FBX/weapon/demo\\.zip`，这样 JSON 中不需要写成 `\\\\`。

### `directory_patterns`

类型：正则字符串数组。

默认行为：缺失时为空。

含义：目录黑名单。扫描时如果目录名或相对目录路径命中任意规则，该目录整棵子树都会被跳过，目录下任何文件都不会被探测、预重命名或解压。

匹配候选：

- 目录名，例如 `weapon`。
- 相对目录路径，例如 `FBX/weapon`。

示例：

```json
{
  "directory_patterns": [
    "weapon",
    "FBX/weapon",
    ".*/weapon",
    "^cache$",
    "^Library/PackageCache"
  ]
}
```

示例含义：

- `"weapon"`：任何目录名或路径中包含 `weapon` 的目录都会跳过。
- `"FBX/weapon"`：跳过相对路径中包含 `FBX/weapon` 的目录。
- `".*/weapon"`：跳过任意层级下名为 `weapon` 的目录。
- `"^cache$"`：只跳过目录名精确等于 `cache` 的目录。

### `filename_patterns`

类型：正则字符串数组。

默认行为：缺失时为空。

含义：文件名黑名单。命中的文件不会被扫描为归档，也不会参与预重命名计划。对于分卷重命名，如果某个 series 指令涉及的源文件命中文件黑名单，整条 series 重命名指令会被丢弃。

匹配候选：

- 完整文件名，例如 `demo.zip`。
- 相对文件路径，例如 `FBX/weapon/demo.zip`。

示例：

```json
{
  "filename_patterns": [
    "^readme\\.zip$",
    ".*\\.unitypackage$",
    "FBX/weapon/demo\\.zip",
    "^do_not_unpack\\.7z$"
  ]
}
```

注意：如果写 `"demo\\.zip"`，它会命中所有路径中包含 `demo.zip` 的文件。若只想命中根目录下的 `demo.zip`，建议写 `"^demo\\.zip$"`。

## `extraction_rules.scene_rules`

`scene_rules` 用于识别游戏或应用运行目录，并保护运行时资源，避免把资源包、应用包、文档容器等误当作普通压缩包递归解压。

重要规则：如果 `scene_rules` 缺失或不是数组，场景识别规则为空，所有目录都会按 `generic` 处理。仓库自带配置提供了 RPG Maker、Ren'Py、Godot、NW.js、Electron 的推荐规则。

基本结构：

```json
{
  "scene_rules": [
    {
      "scene_type": "rpg_maker_game",
      "display_name": "RPG Maker",
      "top_level_dir_markers": {},
      "top_level_file_markers": {},
      "top_level_glob_markers": [],
      "nested_path_markers": {},
      "match_variants": [],
      "weak_match_variants": [],
      "protected_prefixes": [],
      "protected_exact_paths": [],
      "protected_archive_exts": [],
      "runtime_exact_paths": []
    }
  ]
}
```

### `scene_type`

类型：非空字符串。

必填：是。

含义：场景类型 ID，例如 `rpg_maker_game`、`renpy_game`、`godot_game`。程序内部用它查找对应保护规则。

如果缺失或为空，该条规则会被忽略。

### `display_name`

类型：字符串。

默认值：如果缺失，使用 `scene_type`。

含义：日志中显示的人类可读名称。

### `top_level_dir_markers`

类型：对象，键和值都是字符串。

含义：顶层目录标记。扫描目标目录第一层时，如果发现某个目录名，就把对应 marker 加入场景标记集合。

示例：

```json
{
  "www": "www_dir",
  "resources": "resources_dir",
  "game": "game_dir"
}
```

注意：键会被转为小写匹配。

### `top_level_file_markers`

类型：对象，键和值都是字符串。

含义：顶层文件标记。扫描目标目录第一层时，如果发现某个文件名，就把对应 marker 加入场景标记集合。

示例：

```json
{
  "game.exe": "game_exe",
  "package.json": "package_json",
  "data.pck": "data_pck"
}
```

### `top_level_glob_markers`

类型：二维数组，每个元素形如 `[glob_pattern, marker]`。

含义：顶层文件名或目录名的 glob 标记。使用 `fnmatch` 匹配，适合 `*.exe`、`*.pck`、`*.rpa` 这类模式。

示例：

```json
[
  ["*.exe", "runtime_exe"],
  ["*.pck", "pck_pack"]
]
```

### `nested_path_markers`

类型：对象，键和值都是字符串。

含义：嵌套路径标记。如果目标目录下存在指定相对路径，就加入对应 marker。路径建议使用 `/`。

示例：

```json
{
  "www/js/rpg_core.js": "rpg_core",
  "resources/app.asar": "app_asar",
  "game/script.rpy": "script_rpy"
}
```

### `match_variants`

类型：对象数组。

含义：强匹配条件。任意一个 variant 命中后，该目录会被识别为该场景的强匹配目录。

结构：

```json
[
  {
    "all_of": ["resources_dir", "app_exe"],
    "any_of": ["app_asar", "resources_app_dir"]
  }
]
```

匹配逻辑：

- `all_of` 中的 marker 必须全部存在。
- `any_of` 为空时不要求可选 marker。
- `any_of` 非空时至少需要命中一个。

强匹配影响：

- 对扫描根目录，如果识别为强场景目录，整目录可能被跳过递归扫描。
- 对目录内文件，场景保护规则会降低资源包被解压的概率。

### `weak_match_variants`

类型：对象数组。

含义：弱匹配条件。逻辑与 `match_variants` 相同，但匹配强度为 `weak`。

弱匹配影响：不会像强匹配那样直接整目录短路，但会参与目录语义保护。

### `protected_prefixes`

类型：字符串数组。

含义：受保护的相对路径前缀。文件位于这些路径下时，会被视为运行时资源区域。

路径格式：程序内部统一使用 `/`，建议配置也使用 `/`。

示例：

```json
["www/audio", "www/data", "resources", "game", "renpy"]
```

影响：

- 如果文件在受保护路径下，且后缀属于 `protected_archive_exts` 或文件属于分卷关系，会被标记为 `embedded_resource_archive`，最终不解压。
- 如果文件在受保护路径下，且后缀属于 `strict_semantic_skip_exts` 或 `likely_resource_exts_extra`，会降低评分，减少误解压。

### `protected_exact_paths`

类型：字符串数组。

含义：受保护的精确相对路径。

示例：

```json
["data.pck", "resources/app.asar"]
```

### `protected_archive_exts`

类型：字符串数组。

含义：在受保护路径中出现时，应被视为运行时资源包的归档类后缀。

示例：

```json
[".pck", ".asar", ".zip", ".7z", ".rar", ".exe"]
```

风险：这里的后缀只在场景保护命中时生效。配置过宽会导致真实要解压的资源包被跳过；配置过窄会增加误解压运行时资源的风险。

### `runtime_exact_paths`

类型：字符串数组。

含义：运行时入口文件的精确相对路径。命中后文件会被标记为 `game_runtime`，用于语义分类。

示例：

```json
["game.exe", "package.json", "project.godot"]
```

## `post_extract`

`post_extract` 控制一轮或整个任务成功解压后的后处理。

```json
{
  "post_extract": {
    "archive_cleanup_mode": "recycle",
    "flatten_single_directory": true
  }
}
```

### `post_extract.archive_cleanup_mode`

类型：字符串。

可选值：

- `"keep"`：保留原始归档文件，不移动、不删除。
- `"recycle"`：把已成功解压的原始归档文件移动到回收站。
- `"delete"`：直接用系统删除删除已成功解压的原始归档文件。

默认值：`"recycle"`。

非法值回退：`"recycle"`。

补充行为：

- 只处理成功解压的归档及其分卷文件。
- `"keep"` 会禁用通过删除已解压归档释放空间的能力。磁盘空间不足时，程序不会为了释放空间而删除原归档。
- `"delete"` 不经过回收站，请确认已有备份或可重新获取原文件。

### `post_extract.flatten_single_directory`

类型：布尔值。

默认值：`true`。

含义：是否压平只有单个子目录且没有文件的目录结构。

示例：开启时，解压结果如果是：

```text
output/
  package/
    file.txt
```

可能整理为：

```text
output/
  file.txt
```

取值：

- `true`：启用压平。
- `false`：保持解压后的目录结构不变。

风险：压平时如果目标文件名冲突，程序会自动追加 `(1)`、`(2)` 等后缀，但仍建议在重要目录中谨慎使用。

## `recursive_extract`

`recursive_extract` 控制自动递归解压。

类型：正整数、正整数字符串、`"*"` 或 `"?"`。

默认值：`"*"`。

可选模式：

- `1`：只执行第一轮扫描和解压。第一轮完成后执行 `post_extract`，不继续扫描解压结果。
- `2`：第一轮完成后扫描第一轮输出，再解压第二轮。第二轮后执行 `post_extract` 并停止。
- 任意正整数 `N`：最多执行 `N` 轮。
- `"*"`：无限递归模式。持续扫描新解压出的目录，直到没有新的可解压任务。
- `"?"`：交互递归模式。每轮解压完成后先执行 `post_extract`，然后在 CLI 中询问是否继续下一轮。

非法值回退：`"*"`。

注意：

- `"?"` 适合人工控制复杂目录，尤其是第一轮有很多压缩包、后续是否继续需要确认的场景。
- 如果通过非交互环境运行 `"?"`，程序读取不到输入时会停止递归。

## `performance`

`performance` 控制并发和扫描成本。通常只需要调整 `scheduler_profile`，其他字段建议在确实遇到性能或误检成本问题时再修改。

```json
{
  "performance": {
    "scheduler_profile": "auto",
    "scheduler": {
      "initial_concurrency_limit": 0,
      "poll_interval_ms": 0,
      "scale_up_threshold_mb_s": 0,
      "scale_up_backlog_threshold_mb_s": 0,
      "scale_down_threshold_mb_s": 0,
      "scale_up_streak_required": 0,
      "scale_down_streak_required": 0,
      "medium_backlog_threshold": 0,
      "high_backlog_threshold": 0,
      "medium_floor_workers": 0,
      "high_floor_workers": 0
    },
    "max_workers_override": 0,
    "embedded_archive_scan": {
      "stream_chunk_size": 1048576,
      "min_prefix": 32,
      "min_tail_bytes": 4096,
      "max_hits": 3
    }
  }
}
```

### `performance.scheduler_profile`

类型：字符串。

可选值：

- `"auto"`：自动选择调度策略。
- `"conservative"`：保守策略，较低初始并发，适合机械硬盘、外置硬盘或希望降低系统负载的场景。
- `"aggressive"`：激进策略，更高初始并发，适合 CPU 多、内存大、磁盘性能较强的机器。

默认值：`"auto"`。

非法值回退：`"auto"`。

`auto` 当前逻辑：

- CPU 核心数不少于 `12` 且内存不少于 `24 GB` 时，选择 `aggressive`。
- 其他情况选择 `conservative`。

注意：配置中的 `scheduler_profile` 字段仍记录请求值。`auto` 的实际参数会根据机器条件解析为保守或激进默认值。

### `performance.scheduler`

`scheduler` 是高级并发调度参数。所有字段填 `0` 表示使用 `scheduler_profile` 的默认值。除非你明确知道瓶颈在哪里，否则建议保持 `0`。

#### `initial_concurrency_limit`

类型：正整数或 `0`。

含义：初始并发限制。`0` 表示使用 profile 默认值。

profile 默认值：

- `conservative`：`4`
- `aggressive`：`6`

实际并发不会超过 `max_workers_override` 或自动检测出的最大 worker 数。

#### `poll_interval_ms`

类型：正整数或 `0`。

含义：调度器检查磁盘 I/O 和任务积压的间隔，单位毫秒。`0` 表示使用 profile 默认值。

profile 默认值：

- `conservative`：`1000`
- `aggressive`：`500`

运行时下限：即使配置得更低，也会按至少 `100 ms` 处理。

#### `scale_up_threshold_mb_s`

类型：正整数或 `0`。

含义：当平均磁盘 I/O 低于该阈值时，调度器认为还有余量，可能提高并发。单位 MB/s。`0` 表示使用 profile 默认值。

profile 默认值：

- `conservative`：`20`
- `aggressive`：`80`

#### `scale_up_backlog_threshold_mb_s`

类型：正整数或 `0`。

含义：任务积压较多时使用的扩容 I/O 阈值。积压多且平均 I/O 低于该值时，调度器更倾向于提高并发。单位 MB/s。`0` 表示使用 profile 默认值。

profile 默认值：

- `conservative`：`40`
- `aggressive`：`160`

#### `scale_down_threshold_mb_s`

类型：正整数或 `0`。

含义：当平均磁盘 I/O 高于该阈值、worker 接近满载且积压不太高时，调度器可能降低并发。单位 MB/s。`0` 表示使用 profile 默认值。

profile 默认值：

- `conservative`：`140`
- `aggressive`：`400`

#### `scale_up_streak_required`

类型：正整数或 `0`。

含义：连续多少次检查满足扩容条件后才提高并发。`0` 表示使用 profile 默认值。

profile 默认值：

- `conservative`：`2`
- `aggressive`：`2`

#### `scale_down_streak_required`

类型：正整数或 `0`。

含义：连续多少次检查满足降并发条件后才降低并发。`0` 表示使用 profile 默认值。

profile 默认值：

- `conservative`：`3`
- `aggressive`：`3`

#### `medium_backlog_threshold`

类型：正整数或 `0`。

含义：中等任务积压阈值。积压达到该阈值时，动态并发下限可能提升到 `medium_floor_workers`。`0` 表示使用 profile 默认值。

profile 默认值：

- `conservative`：`8`
- `aggressive`：`8`

#### `high_backlog_threshold`

类型：正整数或 `0`。

含义：高任务积压阈值。积压达到该阈值时，动态并发下限可能提升到 `high_floor_workers`。`0` 表示使用 profile 默认值。

profile 默认值：

- `conservative`：`24`
- `aggressive`：`24`

运行时约束：该值会至少不小于 `medium_backlog_threshold`。

#### `medium_floor_workers`

类型：正整数或 `0`。

含义：中等积压时的动态并发下限。`0` 表示使用 profile 默认值。

profile 默认值：

- `conservative`：`2`
- `aggressive`：`4`

#### `high_floor_workers`

类型：正整数或 `0`。

含义：高积压时的动态并发下限。`0` 表示使用 profile 默认值。

profile 默认值：

- `conservative`：`3`
- `aggressive`：`6`

运行时约束：该值会至少不小于 `medium_floor_workers`，且不会超过最大 worker 数。

### `performance.max_workers_override`

类型：非负整数。

默认值：`0`。

含义：覆盖最大 worker 数。

取值：

- `0`：自动检测最大 worker 数。
- 正整数：强制使用该值作为最大 worker 数。

自动检测逻辑：

- 如果系统物理磁盘信息显示 SSD，最大 worker 数为 `max(2, CPU 核心数)`。
- 否则最大 worker 数为 `2`。
- 如果检测失败，也使用 `2`。

风险：设置过高可能让磁盘 I/O 饱和，导致系统卡顿或整体速度反而下降。

### `performance.embedded_archive_scan`

`embedded_archive_scan` 控制对图片、PDF 等载体文件中嵌入式归档的扫描成本。

#### `stream_chunk_size`

类型：正整数。

默认值：`1048576`。

含义：流式扫描时每次读取的字节数。

调参建议：

- 增大：减少读取次数，可能提高大文件顺序扫描效率，但单次内存占用更高。
- 减小：降低单次内存占用，但可能增加读取次数。

#### `min_prefix`

类型：非负整数。

默认值：`32`。

含义：宽松扫描时跳过文件开头多少字节后再查找归档魔数。用于避免把文件本身的头部误判为嵌入式归档。

#### `min_tail_bytes`

类型：正整数。

默认值：`4096`。

含义：宽松扫描命中归档魔数后，要求从命中位置到文件末尾至少剩余多少字节，才认为可能存在嵌入式归档。

调参建议：

- 降低：更容易发现很小的嵌入式归档，但误判更多。
- 提高：更保守，减少误判。

#### `max_hits`

类型：正整数。

默认值：`3`。

含义：宽松扫描最多记录多少个候选命中。达到上限后停止继续查找。

风险：设置过高会增加大文件扫描成本。

## 内置但不可配置的规则

以下底层规则当前固定在代码中，不从 JSON 读取：

- 文件头魔数表：7z、RAR、ZIP、Gzip、Bzip2、XZ 等。
- 弱魔数表：例如可执行文件头。
- 尾部嵌入式归档魔数表。
- 分卷命名识别规则：例如 `.part01.rar`、`.7z.001`、`.001`。
- 伪装归档文件名规则：例如 `.zip.jpg`、`.rar.png`、`.exe.jpg`。

这些规则稳定性较高，普通用户通常很难安全编辑，因此保留在代码内。

## 常见配置示例

### 新增普通归档后缀

```json
{
  "extraction_rules": {
    "extensions": {
      "standard_archive_exts": [".7z", ".rar", ".zip", ".gz", ".bz2", ".xz", ".cbz"]
    }
  }
}
```

### 禁止扫描某个资源目录

```json
{
  "extraction_rules": {
    "blacklist": {
      "directory_patterns": ["^FBX/weapon$"]
    }
  }
}
```

### 禁止处理某些完整文件名

```json
{
  "extraction_rules": {
    "blacklist": {
      "filename_patterns": ["^readme\\.zip$", ".*\\.unitypackage$"]
    }
  }
}
```

### 保留原压缩包且不压平目录

```json
{
  "post_extract": {
    "archive_cleanup_mode": "keep",
    "flatten_single_directory": false
  }
}
```

### 只解压一轮，不递归

```json
{
  "recursive_extract": 1
}
```

### 每轮结束后询问是否继续

```json
{
  "recursive_extract": "?"
}
```

### 降低小文件检测门槛

```json
{
  "extraction_rules": {
    "min_inspection_size_bytes": 0
  }
}
```

### 使用更保守的扫描判定

```json
{
  "extraction_rules": {
    "thresholds": {
      "archive_score_threshold": 8,
      "maybe_archive_threshold": 4
    }
  }
}
```

## 修改建议

建议修改配置后先运行：

```powershell
python smart-unpacker.py scan .\目标目录
python smart-unpacker.py inspect --verbose .\目标目录
```

确认扫描结果符合预期后，再运行：

```powershell
python smart-unpacker.py extract .\目标目录
```

如果启用了 `"archive_cleanup_mode": "delete"`，请务必先确认原文件可恢复或已有备份。
