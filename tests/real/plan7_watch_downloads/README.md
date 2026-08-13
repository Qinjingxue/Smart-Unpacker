# 测试改造计划 · 第 7 条：watch 模拟真实下载场景

对应 `tests/测试改造.txt` 的第 7 条：

- 把 watch 模式的真实下载场景测试迁移到 `tests/real` 并升级；
- 模拟真实 zip / rar / 7z / zstd / tar / 流格式（gzip/bzip2/xz/zstd）的
  普通压缩包、SFX 压缩包、各种形式分卷压缩包、SFX 分卷压缩包写入；
- 分卷顺序混乱到达；密码列表同时有错误密码与正确密码；
- 项目必须按预期处理，文件已经达到后不能没有反应；
- 整个过程记录内存随文件到达数量的变化。

## 与原集成场景的关系

- 原集成场景只覆盖 rar/7z/zip 加密分卷，且关闭了检测管线；
- 本套件已迁移并升级：启用完整检测管线（复用 plan1 配置），覆盖全部支持格式，
  并新增按到达数量采样的内存时间线、实际提交事件和稳定后的反应延迟断言。
- 原场景不再单独保留，避免 watch 分卷到达和完成语义在外部集成目录重复维护。

## 模拟方式

`arrive_slowly` 按真实下载器行为写入：分块（16KB）追加到
`<name>.downloading` 临时文件，每块 fsync 并触发 watch 事件，全部写完后再
`os.replace` 改名为最终文件名并触发 moved 事件；同时覆盖直接写最终文件名的下载器。
`arrive_interleaved` 让多个归档交错下载，另有中断后重新创建 watcher 并续写的场景。
分卷按每个卷逐一分块下载，卷号乱序到达（非头卷随机乱序、头卷最后），另测
启动器先到、数据卷先到且启动器最后到，以及 RAR `part1.exe` 作为真实数据卷。

密码文件 `.sunpack-passwords.txt` 写入 24 个错误密码 + 1 个正确密码；
加密归档全部使用同一个正确密码。

## 八阶段覆盖矩阵

### 阶段 1-2：基线矩阵、反应/完成断言

`test_plan7_plain_and_sfx_downloads.py`：

- 普通：zip / 7z / rar（加密）、tar、tar.gz、tar.bz2、tar.xz、tar.zst、
  gzip、bzip2、xz、zstd；
- SFX：zip / rar / 7z（加密）；
- 记录最后稳定时间、首次有效提交时间、完成时间，并要求稳定后在 15 秒内有反应、
  60 秒内完成。

### 阶段 3：写入方式、交错下载、重启续传

`test_plan7_download_modes.py` 覆盖：

- ZIP + 7z 多归档交错分块；
- 直接写最终文件名；
- 中断下载、关闭 watcher、持久化状态后重新启动并续写。

`test_plan7_lifecycle.py` 进一步覆盖：

- watcher 启动时已有完整文件、非零 quiet window、残留 `.downloading`；
- 临时下载文件被删除后重新完整下载；
- 缺尾分卷后来到达、watcher 重启后续传未完成分卷；
- 同 stem 普通包与 SFX 交错到达；
- 同名归档替换、删除后重新出现；
- 流格式直接写入最终路径；
- 失败归档不产生输出且保留给用户排查。

### 阶段 4：分卷到达顺序

`test_plan7_arrival_orders.py` 覆盖：

- 7z/ZIP SFX 启动器先到；
- 数据卷先到、启动器最后到（保留已约定的极端边界）；
- RAR `part1.exe` 必须作为输入卷而不是 launcher companion。

`test_plan7_split_downloads.py`：

- 分卷：7z（`.001` 数值后缀）、zip（`.001` 数值后缀）、rar（`partN`）；
- SFX 分卷：7z / zip / rar。

### 阶段 5：密码和容器变体

`test_plan7_variants.py` 覆盖 7z header encryption off、ZIP Crypto、ZIP AES-256、
RAR4 header encryption 和 RAR4 data-only；所有场景都同时提供错误密码和正确密码。

### 阶段 6：扩展名伪装与载体前缀

`test_plan7_disguised.py` 覆盖 7z/RAR 伪装扩展名，以及带 JPG 前缀的 ZIP。后者还
回归关系层不能把单盘 EOCD 误当成缺失尾卷的问题。

### 阶段 7：简单嵌入

`test_plan7_embedded.py` 只构造三个独立文件：一个只嵌入 7z、一个只嵌入 ZIP、
一个只嵌入 RAR；不引入 Plan 5 的多段、多格式复杂嵌入。

### 阶段 8：生命周期和清理

`test_plan7_cleanup.py` 验证 SFX 分卷的 launcher 与所有数据卷都进入 owned/cleanup
集合，解压成功后 `archive_cleanup_mode=delete` 会全部清理；各测试还检查 watch 状态
无残留失败、完成路径重放不产生新提交和每次轮询延迟。

Plan 7 要求完整生成能力（7z SFX 模块、RAR/WinRAR 及 zstd.exe）；缺失时直接失败并在上下文记录 `skipped`，避免只验证剩余格式却误报矩阵通过。

## 断言

1. 每个归档的 marker 恰好解出一次，内容与构造一致；
2. 每个归档从“最后一块/最后一个分卷稳定”到解出的延迟小于 60 秒
   （文件已到达但没有反应即失败）；
3. 单文件归档每个恰好提交一次；分卷乱序到达允许对不完整组做探测性提交
   （借后端确认缺卷，属设计行为），要求每个归档至少提交一次；
4. 全部完成后 watch 状态无残留失败，重放已完成路径不产生新提交；
5. 每次 watch 轮询耗时 < 5 秒；
6. 内存时间线：每次归档到达与每次完成各采样一次（parent RSS + worker RSS +
   child 数 + 已到达卷数/归档数），断言到达/完成采样数量覆盖全部归档、
   worker 进程数稳定、parent/worker 内存增长有界
   （< 128MB / < 64MB，宽松上限避免 CI 抖动）。

内存时间线同时写入 `record_property`（`memory_timeline` / `memory_summary`）
并打印为表格。

## 运行

本套件默认运行，无需额外参数：

```powershell
pytest tests/real/plan7_watch_downloads -q
```

## 当前状态

套件默认运行，不再依赖 `slow_real_archive` 标记或额外参数。完整矩阵要求本机具备
7z SFX 模块、RAR/WinRAR 和 `zstd.exe`；缺失时测试直接失败并把缺失能力写入测试上下文，
不会把缩减后的矩阵误报为通过。
