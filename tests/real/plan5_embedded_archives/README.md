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

## 当前状态（已知失败自动记录到 `tests/real/error_records/`，待统一修复）

检测层两个用例当前通过（native 扫描能命中全部 13 个段，整文件也能作为一个任务）。

提取层当前失败，主用例只规划并解出 4/13 段：

- 成功：7z 头加密、rar5 头加密、tar、zip AES-256；
- 缺失：zipcrypto、7z 仅数据、rar5 仅数据、rar4 头加密、rar4 仅数据、
  gzip、bzip2、xz、zstd。

本次运行记录的规划证据显示根因在嵌入扫描结果没有进入规划层：

1. 整个文件顶层已被识别为 zip（carrier_prefix），`embedded_payload_identity`
   的嵌入重扫只作用于“未被识别为压缩包”的目标，`analysis.signature_prepass`
   没有携带完整嵌入候选；规划层只按头/尾签名预处理加各格式 probe 工作。
2. 因此 gzip/bzip2/xz/zstd 完全不可见（压缩流模块只探测视图偏移 0 的流）；
   zipcrypto 的 EOCD probe 未通过（同文件 zip AES-256 通过）；
   7z 仅数据、rar5 仅数据、rar4 的 probe 未给出可提取证据；
   tar 的边界在 PAX 头/载荷处提前结束（本例 40991→53791，实际应到 ~61471）。
3. 已规划出的 rar 段范围 [28859, 84091] 吞掉了中间的 tar/流/垃圾
   （7z 能容忍尾部垃圾所以该段仍解出）；tar 段被截断但 marker 幸存
   （marker 是第一个成员）。
4. 密码探测输入只取第一个段（7z 范围），全错密码时非加密 tar 段也一并报
   “密码错误或未知密码”，因此反向用例当前 0 个非加密段解出。

修复方向（供后续阶段参考）：即使顶层已被识别，也要让嵌入扫描候选进入规划层；
native 为 zip/rar/bzip2/xz/zstd/tar 补齐精确 `end_offset`；压缩流模块支持按命中
偏移探测；嵌入段密码探测输入改为逐段各自提供。
