# 规则插件说明

本文档描述当前版本的检测规则、Fact 采集器和处理器插件接口。项目现在以注册表和三层流水线为准：`precheck`、`scoring`、`confirmation`。

## 总体流程

检测阶段围绕 `FactBag` 工作：

1. 规则声明自己需要的 `required_facts`。
2. 调度器按需调用 Fact 采集器、处理器或关系构建逻辑生成这些事实。
3. 规则读取 facts 和自身配置，返回预检接受/拒绝、加减分或确认结果。
4. 最终分数和确认结果决定文件是否进入解压任务。

默认配置见 `sunpack_config.json` 的 `detection.rule_pipeline`。

## 规则插件

规则类继承 `RuleBase`，并用 `@register_rule(name=..., layer=...)` 注册：

```python
from sunpack.detection.pipeline.rules.base import RuleBase, RuleEffect
from sunpack.detection.pipeline.rules.registry import register_rule


@register_rule(name="my_rule", layer="scoring")
class MyRule(RuleBase):
    required_facts = {"file.path"}
    produced_facts = {"file.detected_ext"}
    config_schema = {
        "score": {
            "type": "int",
            "required": False,
            "default": 5,
            "description": "命中时增加的分数。",
        },
    }

    def evaluate(self, facts, config):
        return RuleEffect.add_score(config.get("score", 5), "my reason")
```

常用类属性：

- `required_facts`：规则运行前必须具备的事实名。
- `produced_facts`：规则会写回 `FactBag` 的事实名，主要用于元数据和校验。
- `config_schema`：允许出现在 `sunpack_config.json` 里的规则配置字段。
- `fact_requirements`：仅 scoring 层使用的条件式事实需求，用来避免不必要的昂贵扫描。

可注册的 `layer`：

- `precheck`：预检层。按配置顺序执行低成本终止型规则，可直接拒绝或直接接受候选，例如场景保护或高置信结构识别。黑名单和过小文件过滤属于 `filesystem.scan_filters`。
- `scoring`：打分层。规则给候选增加或扣减分数，也可写入归一化事实。
- `confirmation`：确认层。通常在分数处于可疑区间时调用 7-Zip 探测或测试。

## 配置 Schema

`config_schema` 会被 `sunpack config validate` 校验。支持的字段类型包括：

- `any`
- `str`
- `int`
- `bool`
- `dict`
- `list`
- `list[str]`
- `list[dict]`
- `dict[str,int]`
- `dict[str,str]`

示例：

```python
config_schema = {
    "enabled_exts": {
        "type": "list[str]",
        "required": True,
        "default": [".zip"],
        "description": "允许命中的扩展名。",
    }
}
```

注意：`default` 只用于说明和元数据，不会自动合并进运行时配置。规则实现必须用 `config.get("field", fallback)` 显式处理默认值。

规则配置里始终允许 `name` 和 `enabled`。其它字段必须在规则的 `config_schema` 中声明，否则配置校验会报错。

## 条件式 Fact 需求

scoring 规则可以通过 `fact_requirements` 限定某些事实只在特定候选上采集。例如嵌入式压缩包分析只对图片、PDF、GIF、WebP 或可疑资源扩展名有意义：

```python
from sunpack.detection.pipeline.rules.fact_requirements import FactRequirement, PathExtensionInConfig


fact_requirements = [
    FactRequirement(
        "embedded_archive.analysis",
        condition=PathExtensionInConfig(
            fields=("carrier_exts", "ambiguous_resource_exts"),
            defaults={
                "carrier_exts": (".jpg", ".png", ".pdf", ".gif", ".webp"),
                "ambiguous_resource_exts": (".dat", ".bin"),
            },
        ),
    )
]
```

调度器会按候选文件和规则配置合并实际需要的 facts。采集器仍应保留廉价的防御性检查，因为它们也可能被测试或工具直接调用。

## Fact 采集器

采集器用 `@register_fact(...)` 注册，负责从候选路径直接产生一个事实：

```python
from sunpack.detection.pipeline.facts.registry import register_fact


@register_fact(
    "file.example",
    type="str",
    description="示例事实。",
)
def collect_example(path: str) -> str:
    return "value"
```

每个采集器必须声明 `type` 和 `description`。返回值会按 schema 类型校验；采集失败时错误会记录在 `FactBag` 中，可通过 `get_error()` 或 `get_errors()` 查看。

如果采集器需要上下文对象，可以在注册时传 `context=True`，函数接收的参数会由普通路径变为上下文。

## 处理器插件

处理器把已有 facts 组合成派生 facts，注册方式如下：

```python
from sunpack.detection.pipeline.processors.registry import register_processor


@register_processor(
    "my_archive_structure",
    input_facts={"file.path", "file.magic_bytes"},
    output_facts={"my_archive.structure"},
    schemas={
        "my_archive.structure": {
            "type": "dict",
            "description": "自定义压缩格式结构判断。",
        },
    },
)
def process_my_archive_structure(context):
    ...
```

处理器适合放派生事实逻辑，例如结构校验、嵌入载荷扫描或场景事实归一化。这样 scoring 规则只消费 facts 做加减分，不需要重复扫描文件。

处理器的输出 fact 同样会写入全局 `FACT_SCHEMA`，规则可以直接在 `required_facts` 中依赖它。

## 当前内置规则

| 规则 | 层 | 作用 |
| --- | --- | --- |
| `scene_protect` | `precheck` | 保护游戏、程序等运行目录中的资源归档。 |
| `zip_structure_accept` | `precheck` | 文件起始魔数命中 ZIP 后，对 EOCD、central directory entry walk 和 local header 回指可信的 ZIP 结构直接接受。 |
| `tar_structure_accept` | `precheck` | 对 ustar header checksum 和 entry walk 可信的 TAR 结构直接接受。 |
| `seven_zip_structure_accept` | `precheck` | 对 start header、next header CRC 和 next header NID 均可信的 7z 结构直接接受。 |
| `rar_structure_accept` | `precheck` | 对 main header CRC 与后续 block/header walk 均可信的 RAR4/RAR5 结构直接接受。 |
| `extension` | `scoring` | 按扩展名组给候选加分。 |
| `embedded_payload_identity` | `scoring` | 消费 `embedded_archive.analysis` 和 `pe.overlay_structure`，按普通载体或 PE overlay 中的归档载荷证据加分。 |
| `seven_zip_structure_identity` | `scoring` | 消费 `7z.structure`，按 7z magic、start header、next header CRC/NID 证据加分。 |
| `rar_structure_identity` | `scoring` | 消费 `rar.structure`，按 RAR magic、main header CRC、second block/header walk 证据加分。 |
| `zip_structure_identity` | `scoring` | 消费 `zip.local_header`，并在 ZIP 起始魔数命中后消费 `zip.eocd_structure`，按 ZIP magic、local header、EOCD/CD、CD entry walk 证据加分。 |
| `tar_structure_identity` | `scoring` | 消费 `tar.header_structure`，按 TAR header checksum、ustar marker 和 entry walk 证据加分。 |
| `archive_container_identity` | `scoring` | 消费 `archive.container_structure`，按 CAB、ARJ、CPIO 结构证据加分。 |
| `compression_stream_identity` | `scoring` | 消费 `compression.stream_structure`，按 gzip、bzip2、xz、zstd 结构证据加分。 |
| `scene_penalty` | `scoring` | 对运行目录资源、弱保护路径和常见资源文件扣分。 |
| `seven_zip_probe` | `confirmation` | 用 7-Zip 轻量探测可疑候选。 |
| `seven_zip_validation` | `confirmation` | 用 7-Zip 测试候选是否可读、是否加密。 |

`blacklist` 和 `size_minimum` 已移到 `filesystem.scan_filters`，会在候选进入 detection 规则流水线前执行。默认流水线使用 `extension`、结构类 identity 规则、`embedded_payload_identity` 和 `scene_penalty`。魔数弱证据归属各格式结构规则；普通载体与 PE overlay 载荷统一由 `embedded_payload_identity` 处理。

## 常用事实名

| Fact | 类型 | 含义 |
| --- | --- | --- |
| `file.path` | `str` | 候选文件路径。 |
| `file.size` | `int` | 文件大小，无法读取时为 `-1`。 |
| `file.magic_bytes` | `bytes` | 文件开头 16 字节。 |
| `file.detected_ext` | `str` | 由内容、探测或嵌入证据推断出的压缩格式扩展名。 |
| `file.magic_matched` | `bool` | 文件开头是否命中强压缩包魔数。 |
| `file.embedded_archive_found` | `bool` | 是否找到载体或资源内嵌压缩包。 |
| `file.probe_detected_archive` | `bool` | 探测类证据是否认为它像压缩包。 |
| `file.probe_offset` | `int` | 嵌入或探测命中的载荷偏移。 |
| `file.validation_ok` | `bool` | 7-Zip validation 是否通过。 |
| `file.validation_encrypted` | `bool` | 7-Zip validation 是否报告加密。 |
| `file.is_split_candidate` | `bool` | 文件名是否像分卷成员。 |
| `file.split_role` | `str` | 分卷关系角色，例如 first/member。 |
| `file.split_members` | `list[str]` | 同一分卷组中的其它成员。 |
| `file.logical_name` | `str` | 分卷或关系组推导出的逻辑名称。 |
| `relation.is_split_related` | `bool` | 候选是否属于分卷关系。 |
| `embedded_archive.analysis` | `dict` | 嵌入式压缩包扫描结果。 |
| `7z.structure` | `dict` | 7z signature、start header CRC、next header CRC 与 NID 检查结果。 |
| `rar.structure` | `dict` | RAR4/RAR5 signature、main header CRC 与 second block/header walk 检查结果。 |
| `7z.probe` | `dict` | 7-Zip 轻量探测结果。 |
| `7z.validation` | `dict` | 7-Zip 测试结果。 |
| `scene.context` | `dict` | 目录场景识别结果。 |
| `scene.scene_type` | `str` | 场景类型。 |
| `scene.match_strength` | `str` | 场景匹配强度。 |
| `scene.is_runtime_resource_archive` | `bool` | 候选是否是运行目录资源归档。 |
| `scene.is_protected_path` | `bool` | 候选是否处在受保护场景路径。 |
| `zip.local_header_plausible` | `bool` | 嵌入 ZIP 的局部文件头是否可信。 |
| `zip.local_header_offset` | `int` | ZIP 局部文件头检查偏移。 |
| `zip.local_header_error` | `str` | ZIP 局部文件头不可信时的原因。 |

完整事实名以 `sunpack/detection/pipeline/facts/schema.py`、各插件注册结果和 `python sunpack.py config validate --json` 的 `registered_facts` 为准。

## 开发和校验

新增规则、采集器或处理器后，建议执行：

```powershell
python sunpack.py config validate --json
pytest tests/unit/test_rule_plugin_contract.py
pytest tests/functional/test_rule_pipeline.py
```

配置校验会检查规则名、配置字段、配置类型、规则声明的 fact 是否存在，以及采集器 schema 是否完整。
