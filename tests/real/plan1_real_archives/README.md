# 测试改造计划 · 第 1 条：统一真实文件测试

对应 `tests/测试改造.txt` 的第 1 条：

- 完整支持格式（zip / rar / 7z / tar 变体 / 流格式）的普通压缩包、SFX、各种形式分卷、SFX 分卷；
- 同名不同格式混合在同一个目录，扫描目录识别，每个都正确解压；
- 断言项目检测的格式与真实格式相同（`file.detected_ext`）。

## 约定

- 所有 tar 变体统一使用 `recursive_extract=*`（递归到内容为止），与运行时覆盖配置等价。
- 顶层检测格式按 `plan1_support.EXPECTED_DETECTED_EXT` 定义：tar 变体检测为外层流格式
  （如 tar.gz -> `.gz`），内容靠递归解出；SFX 检测为内层格式（`.7z/.zip/.rar`），容器为 `pe`。
- 测试失败时，`tests/real/conftest.py` 会把详细错误（断言、捕获输出、用例上下文）
  自动写入 `tests/real/error_records/`，每次运行开始时清空，方便统一修复。

## 文件

- `test_plan1_plain_matrix.py`：普通压缩包 + 伪装后缀，12 种格式。
- `test_plan1_split_matrix.py`：7z/zip/rar 分卷命名矩阵 + 单逻辑流检测。
- `test_plan1_sfx_matrix.py`：7z/zip/rar SFX 与 SFX 分卷。
- `test_plan1_mixed_directory.py`：同名不同格式混合目录、同 stem 分卷混合目录。
- `test_plan1_format_variants.py`：结构变体——流式 zip（数据描述符）、ZIP64、
  非 solid 7z、RAR4、RAR4 分卷、多成员 gzip、多流 bzip2/xz、xz SHA-256、
  多帧 zstd。

## 说明

- ZIP64 使用“小 ZIP64”样本：只有 2 个条目（约 4KB），把结尾记录改写为
  ZIP64 EOCD + locator + 经典 EOCD（哨兵值），7z 与 python zipfile 均可正常校验解压，
  避免用 6.5 万条目触发 ZIP64 拖慢测试。
- zip `.z01/.z02/.zip` 传统分卷命名暂未纳入：7z 生成的 `-v` 分卷不是真正的
  pkzip 多盘（改名后连 7z 自己都解不开），生成器不支持该形式。
