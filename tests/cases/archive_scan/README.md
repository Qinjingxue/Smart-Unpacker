# Archive Scan Cases / 归档扫描用例

这个目录用于放“数据驱动”的扫描测试。每个子目录都是一个独立测试用例，测试系统会自动发现并执行，不需要修改 Python 测试代码。

目录结构：

```text
tests/cases/archive_scan/
  case_name/
    case.json
    files/
      sample.zip
      normal.txt
      nested/
        disguised.bin
```

测试逻辑：

1. pytest 自动扫描 `tests/cases/archive_scan/*/case.json`。
2. 把该用例的 `files/` 目录复制到临时工作区。
3. 使用 `case.json` 指定的配置运行检测。
4. 按 `expect` 检查每个文件是否被判定为压缩包。

## case.json 模板

```json
{
  "name": "plain text is not archive",
  "config": "archive_scan_full",
  "files_dir": "files",
  "enabled": true,
  "expect": [
    {
      "path": "notes.txt",
      "should_extract": false,
      "decision": "not_archive",
      "max_score": 0
    }
  ]
}
```

## 顶层字段

| 字段 | 类型 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | `string` | 否 | 用例目录名 | 测试显示名称，建议写清楚场景。 |
| `config` | `string` | 否 | `archive_scan_full` | 使用的测试配置名称。 |
| `files_dir` | `string` | 否 | `files` | 样本文件目录，相对于当前 case 目录。 |
| `enabled` | `boolean` | 否 | `true` | 设为 `false` 时跳过该 case，不会被参数化。 |
| `expect` | `array` | 是 | 无 | 预期结果列表，每一项对应一个被扫描文件。 |

## config 可选值

常用值：

| 值 | 说明 |
| --- | --- |
| `archive_scan_full` | 推荐默认值。启用大小阈值、场景保护、扩展名打分、归档身份识别、场景扣分和 7-Zip confirmation。 |
| `minimal` | 极简配置，主要用于基础规则测试。 |
| `embedded_archive_loose` | 用于宽松扫描嵌入式归档。 |
| `embedded_archive_carrier_tail` | 用于测试图片/PDF/WebP 等载体尾部附加压缩包。 |
| `scene_protect_enabled` | 用于测试场景保护 hard stop。 |
| `scene_penalty_runtime` | 用于测试运行时资源目录扣分。 |

这些配置定义在 `tests/helpers/config_factory.py`。普通 archive scan case 建议使用 `archive_scan_full`。

## expect 字段

`expect` 是数组，每一项描述一个文件的预期判定。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `path` | `string` | 是 | 文件相对路径，以 `files/` 目录为根，使用 `/` 分隔。 |
| `should_extract` | `boolean` | 是 | 是否应该被判定为可解压归档。 |
| `decision` | `string` | 否 | 精确判定结果。 |
| `min_score` | `integer` | 否 | 最低允许分数。 |
| `max_score` | `integer` | 否 | 最高允许分数。 |
| `matched_rules_include` | `array<string>` | 否 | 要求命中的规则名列表。 |

## decision 可选值

| 值 | 含义 |
| --- | --- |
| `archive` | 判定为压缩包，`should_extract` 通常为 `true`。 |
| `not_archive` | 判定为非压缩包，`should_extract` 为 `false`。 |
| `maybe_archive` | 分数处于可疑区间，但 confirmation 没有最终确认。通常不解压。 |

注意：如果只关心“是不是压缩包”，只写 `should_extract` 即可；只有需要锁定具体状态时才写 `decision`。

## matched_rules_include 常见值

| 规则名 | 含义 |
| --- | --- |
| `extension` | 扩展名规则命中，例如 `.zip`、`.7z`。 |
| `archive_identity` | 文件内容/魔数/嵌入归档身份识别命中。 |
| `scene_penalty` | 场景扣分规则参与计算。 |
| `seven_zip_probe` | 7-Zip 轻量探测确认或拒绝。 |
| `seven_zip_validation` | 7-Zip 测试确认或拒绝。 |
| `scene_protect` | 场景保护 hard stop 命中。 |
| `size_minimum` | 文件大小低于检查阈值。 |

## 示例

普通文本不是压缩包：

```json
{
  "name": "plain text is not archive",
  "expect": [
    {
      "path": "notes.txt",
      "should_extract": false,
      "decision": "not_archive",
      "max_score": 0
    }
  ]
}
```

真实压缩包应该被识别：

```json
{
  "name": "real zip is archive",
  "expect": [
    {
      "path": "sample.zip",
      "should_extract": true,
      "decision": "archive",
      "matched_rules_include": ["extension"]
    }
  ]
}
```

伪装扩展名但内容是真归档：

```json
{
  "name": "disguised 7z bin is archive",
  "expect": [
    {
      "path": "payload.bin",
      "should_extract": true,
      "decision": "archive",
      "matched_rules_include": ["archive_identity"]
    }
  ]
}
```

随机文件伪装成 `.7z` 应该被拒绝：

```json
{
  "name": "fake 7z random data is rejected",
  "expect": [
    {
      "path": "fake.7z",
      "should_extract": false,
      "decision": "not_archive",
      "matched_rules_include": ["extension", "seven_zip_probe"]
    }
  ]
}
```

## 新增用例步骤

1. 在 `tests/cases/archive_scan/` 下新建一个目录，例如 `fake_7z_random_rejected/`。
2. 在里面创建 `files/`，把样本文件放进去。
3. 创建 `case.json`，写入 `expect`。
4. 运行：

```powershell
pytest tests/runners/test_archive_scan_cases.py -q
```

新增 case 不需要修改 Python 代码。
