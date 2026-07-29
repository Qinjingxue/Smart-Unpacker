# Analysis / Detection 统一能力重构指导

## 目标

将所有归档结构读取、格式探测、边界计算、完整性观察和深度结构图能力统一到
`sunpack.analysis`。`sunpack.detection` 保留 fact pipeline、规则、评分、候选授权和
现有公开行为，但格式 processor 最终只负责：

1. 按需请求 Analysis capability；
2. 将中立 observation 投影为现有 FactBag 字段；
3. 不再实现或直接绑定格式解析算法。

`ArchiveAnalysisReport` 继续作为聚合报告；底层新增的无损 observation 同时供
Detection、未来的 Inspect 和 report composer 使用。本轮重构不提前建立 Inspect，
也不改变 repair loop 调度。

## 不可破坏的约束

- Detection 的 fact 名、字段语义、规则分数、accept/reject 行为默认保持兼容。
- Analysis 保留 file、multi-volume、embedded-offset、file-range、concat-range 和
  patched `ArchiveState` 的能力。
- 不以较弱实现覆盖较强实现。若两侧各有独特能力，先组合，再删除重复入口。
- Header plausibility 不等于完整可解压；只有完整 validator/7z.dll/verification 可以
  提供相应级别的完整性结论。
- Analysis 输出中立事实，不包含 detection score、`should_extract` 或 repair action。
- Detection 命名先验、split layout prior、规则解释继续留在 Detection。
- 每种格式单独迁移、测试和提交。任一阶段均应保持仓库可运行、可回退。

## 目标调用结构

```text
AnalysisSource + AnalysisRequest
            |
            v
  Analysis capability runtime
            |
            +--> raw FormatObservation --> Detection fact projection --> rules
            |
            +--> report composer --> ArchiveAnalysisReport
            |
            +--> future Inspect projection
```

## 公共能力分层

通用 capability：

- `SIGNATURE_PREPASS`
- `BINARY_PROFILE`
- `FORMAT_PROBE`
- `FORMAT_DEEP_STRUCTURE`
- `FORMAT_FULL_VALIDATION`
- `EMBEDDED_SCAN`

格式粒度由 probe spec 表达，避免为所有格式建立不断膨胀的平铺枚举：

```python
AnalysisRequest(
    capabilities={AnalysisCapability.FORMAT_PROBE},
    probes={
        "rar": RarProbeSpec(level="prefix", max_blocks=2),
        "zip": ZipProbeSpec(local_header=True, eocd=True),
    },
)
```

成本等级：

| 等级 | 示例 |
| --- | --- |
| CHEAP | magic、signature、单 header |
| STANDARD | EOCD、7z start header、RAR 前两个 block |
| EXPENSIVE | 完整 stream validation、RAR block chain、ZIP directory walk |
| DEEP | embedded full scan、ZIP structure graph |

后续 budget 应逐步支持：`max_read_bytes`、`max_candidates`、`max_entries`、
`max_blocks`、`allow_decompression`、`allow_full_stream_scan`。

## Observation 与聚合报告

公共底层返回无损 observation，不能只返回被压缩过的 `ArchiveFormatEvidence.details`：

```python
FormatObservation(
    format,
    source_identity,
    start_offset,
    capabilities,
    raw,
    damage_flags,
    boundary,
    integrity,
)
```

- Detection projection 保持当前 `7z.structure`、`rar.structure`、
  `tar.header_structure`、`compression.stream_structure`、`zip.*` facts。
- report composer 将 observation 转换为 evidence、selected、segments、confidence。
- 原始格式字段必须保留，供 repair model、训练和诊断图使用。

## 分格式迁移计划

### 阶段 A：7z

- 以 reader-based `probe_seven_zip` 为核心。
- 保留签名、版本、start-header CRC、next-header range/CRC/NID、`strong_accept`。
- 保留 Analysis 的任意 offset、多候选、segment、patched/multi-volume 能力。
- Detection 只请求 offset 0 并投影为原 `7z.structure`。
- 验收：现有 7z detection rules 与 analysis tests 行为不变。

### 阶段 B：RAR

- 统一 QUICK/PREFIX/FULL block-walk level。
- CRC 字段由底层明确返回，Detection 不再根据 `blocks_checked` 推测。
- 保留 Analysis 的 encrypted/truncated 分类、end block、embedded offset。
- 验收：RAR4/RAR5、分卷、加密 header、截断 archive 均有覆盖。

### 阶段 C：TAR

- 将 Detection 的 checksum、numeric fields、typeflag、payload range 等字段迁入
  reader-based probe。
- 保留 Analysis 的任意 offset、64-entry walk、zero end blocks 和 segment。
- Detection projection 暂时保留现有 `fuzzy_*` 字段名。
- 普通文件使用 native walker；Patched 与 multi-volume reader fallback 提供相同字段、
  checksum、payload range 和 walk 语义，并由一致性测试约束。

### 阶段 D：压缩流

- 将 Detection 的完整 bounded validator 迁入 Analysis。
- 分离 HEADER、BOUNDARY、FULL_VALIDATION、COMPRESSED_TAR 能力。
- 修正“header plausible 即 extractable”的过强语义。
- 保留 gzip/bzip2/xz/zstd 的原始详细字段和多流 embedded boundary。
- path validator 未 reader 化前允许内部双实现，但公共入口只能在 Analysis。

### 阶段 E：ZIP 基础能力

- 统一 strict local header；采用更严格的 version/method/range 规则。
- 统一 EOCD candidate、ZIP64、SFX archive offset 和 multi-volume logical offset。
- Detection 的 `zip.local_header`、`zip.eocd_structure` 字段保持兼容。

### 阶段 F：ZIP 深度能力

- 将 directory consistency 暴露为 Analysis capability。
- 将 structure graph 暴露为 Analysis capability，完整保留 nodes、edges、
  violations、explanations、summary 和 repair diagnosis 字段。
- 初期允许 path-only，随后再迁为 reader-based 以支持 patched/multi-volume。

### 阶段 G：清理

- 删除 Detection 中 direct native format wrappers。
- Processor 只保留 request 构造和 fact projection。
- 收敛 session cache、capability cache 和 identity key。
- 更新开发边界、配置文档、知识图谱和性能基线。

## 每阶段固定验收流程

1. 冻结旧 processor raw payload 的契约样本。
2. 在 Analysis 增加 observation/capability，不改 Detection rule。
3. 新旧实现对同一语料逐字段比较。
4. Detection processor 改为 projection adapter。
5. 运行对应格式 unit/functional/integration/performance tests。
6. 运行全量 unit tests 和 `git diff --check`。
7. 独立提交并重建知识图谱。
8. 只有新入口覆盖所有消费者后才删除旧实现。

## 停止条件

出现以下情况时不得直接猜测或继续删除旧实现：

- 官方规范与当前字段语义冲突；
- 单文件、多卷、patched source 得出不同结构结论；
- Detection score/decision 发生未解释变化；
- repair model 所需 raw field 丢失；
- 完整校验被较弱的 header probe 替代；
- 性能或读取预算出现数量级回退。

## 权威格式资料

- 7z：<https://www.7-zip.org/7z.html>
- RAR 5.0 technote：<https://www.rarlab.com/technote.htm>
- ZIP PKWARE APPNOTE：<https://support.pkware.com/pkzip/appnote>
- gzip RFC 1952：<https://www.rfc-editor.org/rfc/rfc1952>
- Zstandard RFC 8878：<https://www.rfc-editor.org/rfc/rfc8878>
- bzip2 官方文档：<https://sourceware.org/bzip2/docs.html>
- POSIX ustar 参考：<https://www.gnu.org/software/tar/manual/html_chapter/Formats.html>

若实现细节未在摘要页明确，应进一步读取对应正式规范、官方源码或标准文本；
第三方文章只能作为线索，不能作为结构判断的最终依据。

## 进度

- [x] Phase 1：Embedded 能力并入 Analysis。
- [x] Phase 2：建立公共 source/request、capability 和 `ArchiveAnalyzer` facade。
- [x] Phase 3A：7z observation 与 Detection projection。
- [x] Phase 3B：RAR QUICK/FULL。
- [x] Phase 3C：TAR header/walk。
- [x] Phase 3D：compression stream validation。
- [x] Phase 3E：ZIP local/EOCD。
- [x] Phase 3F：ZIP consistency/graph。
- [x] Phase 3G：重复实现清理与最终回归。

最终边界审计：Detection format processors 不再导入 `sunpack_native`，也不直接调用
`view.probe_*`；它们只构造 Analysis source/options 并投影 observation。为兼容已有
Python 调用者而暂留的 `inspect_*` 函数均为转调 Analysis 的薄 facade，不拥有解析、
缓存或格式判断实现。
