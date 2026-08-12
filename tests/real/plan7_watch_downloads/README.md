# 测试改造计划 · 第 7 条：watch 模拟真实下载场景

对应 `tests/测试改造.txt` 的第 7 条：

- 把 watch 模式的真实下载场景测试迁移到 `tests/real` 并升级；
- 模拟真实 zip / rar / 7z / zstd / tar / 流格式（gzip/bzip2/xz/zstd）的
  普通压缩包、SFX 压缩包、各种形式分卷压缩包、SFX 分卷压缩包写入；
- 分卷顺序混乱到达；密码列表同时有错误密码与正确密码；
- 项目必须按预期处理，文件已经达到后不能没有反应；
- 整个过程记录内存随文件到达数量的变化。

## 与旧测试（tests/integration/test_watch_split_download_order.py）的关系

- 旧测试只覆盖 rar/7z/zip 加密分卷，且关闭了检测管线；
- 本套件迁移并升级：启用完整检测管线（复用 plan1 配置），覆盖全部支持格式，
  并新增按到达数量采样的内存时间线。

## 模拟方式

`arrive_slowly` 按真实下载器行为写入：分块（16KB）追加到
`<name>.downloading` 临时文件，每块 fsync 并触发 watch 事件，全部写完后再
`os.replace` 改名为最终文件名并触发 moved 事件。分卷则按每个卷逐一分块下载，
卷号乱序到达（非头卷随机乱序、头卷最后），验证 watch 不会在卷未齐时误判，
卷齐后会自动重试完成。

密码文件 `.sunpack-passwords.txt` 写入 24 个错误密码 + 1 个正确密码；
加密归档全部使用同一个正确密码。

## 覆盖矩阵

`test_plan7_plain_and_sfx_downloads.py`（11 个归档）：

- 普通：zip / 7z / rar（加密）、tar、gzip、bzip2、xz、zstd；
- SFX：zip / rar / 7z（加密）。

`test_plan7_split_downloads.py`（6 个归档）：

- 分卷：7z（`.001` 数值后缀）、zip（`.001` 数值后缀）、rar（`partN`）；
- SFX 分卷：7z / zip / rar。

工具缺失（Rar.exe / zstd.exe）时对应归档自动跳过并在上下文记录 `skipped`。

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

本套件沿用真实归档矩阵的 slow 标记：

```powershell
pytest tests/real/plan7_watch_downloads --run-slow-real-archives -q
```

## 当前状态

两个用例均通过（本机实测：普通+SFX 约 4.5s，分卷乱序约 9s）。
