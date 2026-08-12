# 测试改造计划 · 第 4 条：加密分卷缺失卷行为

对应 `tests/测试改造.txt` 的第 4 条：

- 加密 zip / rar / 7z 的分卷压缩包与 SFX 分卷压缩包；
- 每个格式每种类型分别模拟：缺失头卷、缺失尾卷、缺失中间卷，
  以及只剩中间卷、只剩头卷、只剩尾卷；
- 密码列表给出正确密码；
- 期望行为：要么正确报“缺失分卷”，要么扫描阶段不当成压缩包而忽略。

## 断言

`assert_missing_volume_or_ignored`：满足以下任一即通过——

1. 失败分类包含 `FailureKind.MISSING_VOLUME`（含“可能缺失分卷”）；
2. 完全被忽略：0 成功、无失败任务（扫描阶段未识别为压缩包）。

其余结果（正常解压、报密码错误/损坏但未报缺失分卷等）均判为失败并记录。

## 文件

- `test_plan4_split_missing_volumes.py`：普通分卷 zip/rar/7z × 6 种场景。
- `test_plan4_sfx_split_missing_volumes.py`：SFX 分卷 zip/rar/7z × 6 种场景。

夹具每个分卷包 7 个左右分卷（620KB 载荷），保证头/中/尾卷可明确区分。

## 场景定义

- 普通分卷：头卷 = `.001`（7z/zip）或 `part1.rar`（rar）。
- SFX 分卷：zip/7z 的 `.exe` 只是启动器（不含数据），头卷按第一个数据卷
  `.001` 计算，启动器保留在目录内但不参与删卷；rar 的 `part1.exe` 本身就是
  数据头卷。

## 已知失败（自动记录到 `tests/real/error_records/`，待统一修复）

- RAR 分卷号不连续（缺头卷/中间卷）时，`sunpack/passwords/verifier/rar_fast.py`
  抛出未捕获的 `ValueError: structured volume numbers must be contiguous from one`，
  管线直接崩溃，既没有报缺失分卷也没有在扫描阶段忽略。
