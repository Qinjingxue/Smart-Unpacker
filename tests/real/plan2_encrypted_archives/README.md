# 测试改造计划 · 第 2 条：加密压缩包 + 100 密码混合列表

对应 `tests/测试改造.txt` 的第 2 条：

- 加密 zip / rar / 7z 的普通压缩包、SFX、各种形式分卷、SFX 分卷；
- 给项目密码列表加入正确 + 错误混合的 100 个密码，项目必须识别出正确密码并解压。

## 覆盖

- `test_plan2_plain_encrypted.py`：
  - zip：ZipCrypto、AES-128、AES-256，以及 Deflate64/BZip2/LZMA/PPMd 方法加密；
  - rar：RAR5 头部加密（-hp）、仅数据加密（-p）、RAR4 头部加密、RAR4 仅数据加密；
  - 7z：头部加密（-mhe=on）、仅数据加密（-mhe=off）、非 solid 加密，以及 LZMA/PPMd/BZip2/Deflate 方法加密。
- `test_plan2_sfx_encrypted.py`：7z/zip/rar SFX 加密、SFX 分卷加密。
- `test_plan2_split_encrypted.py`：复用第 1 条的全部分卷命名方案，加密版本。

每个用例密码列表固定 100 个：99 个唯一错误密码 + 正确密码插在第 63 位。

## 已知失败（自动记录到 `tests/real/error_records/`，待统一修复）

- RAR4 加密（-ma4）在密码列表混入错误密码时整体失败（即使只有 2 个错误密码）。
  单独给正确密码可以解压，样本经 7z/RAR 校验合格，属于密码探测路径的产品问题。
- 7z/zip 的 SFX 分卷 `.exe` 检测返回 0 命中（与第 1 条同一问题），但解压本身成功。
- 加密 RAR 分卷 + 伪装命名（`payload.part1.rar.trash.pkg`）只识别出 1 个成员：
  明文版本正常，加密头无法做结构确认时，文件名兜底模式没有把该命名识别为分卷。
