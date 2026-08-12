# 测试改造计划 · 第 3 条：全错密码 100 个，正确报密码错误

对应 `tests/测试改造.txt` 的第 3 条：

- 加密 zip / rar / 7z 的普通压缩包、SFX、各种形式分卷、SFX 分卷；
- 给项目密码列表加入 100 个全部错误的密码，项目必须正确报密码错误。

## 覆盖

- `test_plan3_plain_wrong_passwords.py`：zip（ZipCrypto/AES-128/AES-256 + 4 种方法）、
  rar（RAR5 头部/仅数据、RAR4 头部/仅数据）、7z（头部/仅数据/非 solid + 4 种方法）。
- `test_plan3_sfx_wrong_passwords.py`：7z/zip/rar SFX 加密、SFX 分卷加密。
- `test_plan3_split_wrong_passwords.py`：13 种分卷命名方案加密版。

断言：0 成功、有失败任务、`FailureInfo.is_password_failure` 为真、marker 未解出。
错误详情（失败任务文本、failure kinds、是否判为密码错误）自动记录到
`tests/real/error_records/`。

与第 2 条共用 `tests/real/encrypted_cases.py` 的用例表。

## 已知失败（自动记录到 `tests/real/error_records/`，待统一修复）

按产品自身的密码失败定义（`PASSWORD_FAILURE_KINDS = {password_required, wrong_password}`），
以下用例没有报成密码错误：

- RAR4 头部加密：报 `UNSUPPORTED`（应为密码错误）；
- RAR4 仅数据加密：报 `DAMAGED`（应为密码错误）；
- ZipCrypto 假阳性：ZipCrypto 只有 1/256 检查位，随机错误密码列表里若恰好有候选
  命中检查位，最终分类会变成 `PASSWORD_INCONCLUSIVE`（“无法确认压缩包的密码状态”）
  而不是确定的 `WRONG_PASSWORD`。固定错误列表下同一用例能稳定报 `WRONG_PASSWORD`
  （已验证 3/3），因此这属于程序“密码确认机制”的不足：命中检查位的候选被当作
  可能密码后，后续 CRC 失败没有回退成密码错误。测试保持原样，用它暴露该问题，
  作为后续统一修复项（表现为随机性抖动，zip / SFX zip / 加密分卷 zip 都可能触发）。
- 7z 仅数据加密（`-mhe=off`）：部分错误密码串会报 `DAMAGED` 而不是 `WRONG_PASSWORD`
  （12 次随机密码串中出现 2 次；固定列表稳定报 `WRONG_PASSWORD`）。同样属于密码
  确认机制不足：错误候选解出垃圾数据后的失败路径没有统一归类为密码错误。
