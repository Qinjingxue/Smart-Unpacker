# 测试改造计划 · 第 5 条：单文件多格式嵌入压缩段

对应 `tests/测试改造.txt` 的第 5 条：

- 一个文件内部嵌入大量不同格式加密压缩段，压缩段之间有垃圾数据；
- 给项目正确密码，要能够识别出其中所有加密压缩段并分别全部解压。

## 测试文件构造

`plan5_support.build_embedded_mixed_case` 生成单一文件 `plan5_embedded.bin`，
布局严格按 `[垃圾0][压缩段1][垃圾1][压缩段2]…[垃圾N]` 重复，覆盖全部支持格式：

- 加密段（共用同一个正确密码）：
  zip（ZipCrypto、AES-256）、7z（头加密 `-mhe=on`、仅数据 `-mhe=off`）、
  rar（RAR5 头加密 `-hp`、RAR5 仅数据 `-p`、RAR4 头加密、RAR4 仅数据）；
- 非加密段：tar、gzip、bzip2、xz、zstd。

垃圾数据规则：

- 每个垃圾块用独立 RNG 种子生成、长度在 192B~6KB 之间随机，块间两两不同；
- 组装完成后立即用 `scan_embedded_archives` 验证每个构造段（格式 + 偏移）都被命中，
  随机垃圾撞出可验证签名导致缺段时换盐值重新组装（有界重试）；
- 文件扩展名必须用中性的 `.bin`：不能用 `.zip/.rar/.7z`
  （否则触发 `input_planning._is_damaged_native_archive_fallback` 抑制段提取），
  也不能用 `.gz/.bz2/.xz/.zst`（否则顶层会被当普通流解掉）。

rar 依赖 `tools/Rar.exe`、zstd 依赖 `tools/zstd.exe`，工具缺失时自动跳过对应段，
并在用例上下文记录 `skipped_formats`。

## 断言分层

1. 检测层（`test_plan5_embedded_detection.py`）：
   - native `scan_embedded_archives` 命中每个构造段（格式 + 起始偏移），
     且垃圾块两两不同；
   - 整个混合文件在扫描阶段恰好成为一个待处理任务。
2. 提取层（`test_plan5_mixed_embedded.py` 主用例）：
   `run_plan1_pipeline` 全成功（1 成功 / 0 失败），每个段的唯一 marker
   （`p5_<variant>.marker.txt`，内容 `edge::p5_<variant>`）都被解出。
3. 反向用例（`test_plan5_wrong_password_partial.py`）：
   全错密码时加密段失败并上报密码错误，非加密段仍应解出。

## 文件

- `plan5_support.py`：段矩阵、垃圾生成、文件组装与三层断言。
- `test_plan5_embedded_detection.py`：检测层两个用例（native 覆盖 + 单任务扫描）。
- `test_plan5_mixed_embedded.py`：主用例（正确密码全量解压）。
- `test_plan5_wrong_password_partial.py`：全错密码的部分成功行为。
- `test_plan5_large_embedded.py`：128 个真实归档循环嵌入，覆盖多种容器和压缩方法。

## 当前状态

原有 13 段检测/提取/错误密码用例当前通过。新增 128 段用例的检测层和整体任务处理已通过，
但其中 16 个 `tar.gz/tar.bz2/tar.xz/tar.zst` 嵌入段的 marker 未能最终解出，保留该用例用于
暴露“嵌入压缩流后的 tar 递归提取”缺口。

修复方向：让嵌入段在非零偏移处继续递归识别/解出 tar 内容，并保证流格式的边界不会吞掉
相邻嵌入段。
