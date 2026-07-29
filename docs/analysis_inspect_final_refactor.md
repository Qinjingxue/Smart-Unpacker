# Analysis / Inspect 最终重构指导

## 目的

本轮重构完成 `sunpack.analysis` 的最终收口：Analysis 只提供归档读取、格式探测、
结构观察、边界判断和聚合报告等通用能力，不再承担主流程 stage、`ArchiveTask`
调度、repair loop 编排或知识写入。

最终依赖方向固定为：

```text
主流程 -> Detection -> Analysis
主流程 -> ArchiveInput planning -> Extraction -> Verification
Verification --需要修复--> Repair loop -> Inspect -> Analysis
CLI/诊断工具 -------------------------------> Analysis
```

`Analysis` 不得依赖 Detection、Inspect、Repair、Coordinator 或 `ArchiveTask`。
`Inspect` 是 repair loop 的反馈层：把待修复或已应用 patch 的归档状态转换为
Analysis source，调用 Analysis，再把中立报告投影为 repair 可消费的反馈。

## 不可破坏的约束

- Detection 的 decision、score、matched rules、fact payload 和候选授权行为保持兼容。
- 正常主流程最终不再经过独立 Analysis stage。
- Detection 可以调用 Analysis 能力，但 Detection 自己拥有规则、评分和输入规划。
- Inspect 只服务 repair loop，不决定 extraction/verification 的最终成败。
- Analysis 保留 file、multi-volume、patched、embedded、file-range 和 concat-range 能力。
- 不以较弱实现覆盖较强实现；格式语义不确定时查阅官方规范后再改。
- 每个阶段独立测试、审查影响并保持可回退。

## 最终模块边界

### Analysis 保留

- `AnalysisSource`、`AnalysisRequest`、capability 和 budget。
- `SharedBinaryView`、`MultiVolumeBinaryView`、`PatchedBinaryView`。
- 7z、RAR、TAR、ZIP、压缩流和 embedded 的底层 probe。
- signature prepass、fuzzy profile、structure modules 和 report composer。
- 单个分析请求内部必需的执行顺序和模块异常隔离。

重构前 `ArchiveAnalysisScheduler` 中的 `prepass -> fuzzy -> structure -> embedded fallback`
不是业务调度，而是复合分析能力的内部实现。最终应改名为内部
`AnalysisEngine`/`AnalysisRuntime`，不再作为公共 scheduler 暴露。线程池的创建、
生命周期和跨任务并发策略由调用层负责，并通过依赖注入提供。

### Inspect 拥有

- `ArchiveState`、repair candidate 到 `AnalysisSource` 的转换。
- repair 状态的分析请求、预算和缓存。
- `ArchiveAnalysisReport` 到 `InspectionFeedback` 的转换。
- repair knowledge/format evidence 的投影。
- repair 前、repair 后和 patched candidate 的状态反馈。
- 可选的前后状态 delta：新问题、已修复问题、边界与置信度变化。

### Detection / 输入规划拥有

- Analysis observation 到 Detection facts 的投影。
- embedded segment 选择、specific container 优先级和 composite 遮蔽规则。
- logical offset 到单文件/多卷 physical ranges 的映射。
- segment 到 `ArchiveInputDescriptor`、logical name 和任务的构造。
- 任务授权、评分、排序和去重。

### 其他层拥有

- Analysis report/Inspection feedback 写入 `ArchiveTask`：Inspect projector。
- ZIP runtime evidence：Verification knowledge/projector。
- CLI `inspect --analyze` 的展示摘要：CLI 层。
- 跨任务批处理、并发和 executor 生命周期：Coordinator/调用层。

## 第一阶段：建立 Inspect

新增建议结构：

```text
sunpack/inspect/
    __init__.py
    request.py
    result.py
    source.py
    service.py
    projector.py
    cache.py
```

公共入口使用 `ArchiveInspector`；Detection CLI 编排器已明确命名为
`coordinator.detection_inspector.DetectionInspectOrchestrator`。

`InspectionFeedback` 至少包含：format、status、confidence、damage flags、可信边界、
segments、container/structure integrity、认证提示和可选原始 Analysis report。

迁入 Inspect：

- `ArchiveAnalysisScheduler.analyze_task` 和 descriptor/task source adapter。
- `ArchiveAnalysisStage.refresh_task_analysis`。
- patched state report cache。
- report 到 repair knowledge/ArchiveState 的投影。
- repair training 中刷新修复状态的入口。

接入 repair beam 时先 shadow 运行，不改变排序；完成结果对比后再替换当前只返回
candidate confidence 的占位 `analyze` callback。

## 第二阶段：迁出调度、构造与知识投影

从 `analysis.stage` 迁出以下输入规划逻辑：

- extractable segment 筛选；
- compressed stream 与 tar container 的特异性优先；
- whole-file composite 遮蔽；
- password-required embedded segment；
- 多卷 logical range 到 physical range 的转换；
- `ArchiveInputDescriptor` 和 logical name 构造。

这些能力进入 Detection/input planner。若 Detection 现有 facts 不足，planner 应显式
调用 Analysis capability 补充 observation，而不是保留主流程 Analysis stage。

拆解 `analysis.knowledge`：

- repair report 投影进入 Inspect；
- embedded/input facts 进入 Detection/input planner；
- ZIP runtime evidence 进入 Verification；
- 中性的 format evidence 投影进入 support 或 Inspect；
- Analysis 内仅允许纯 DTO 转换，不允许写 `ArchiveTask`。

跨任务 grouping、task executor、task report cache 属于上层调度。迁移时避免把整个旧
stage 改名后长期保留；只暂存仍有消费者的行为，待第三阶段删除。

## 第三阶段：从主流程移除 Analysis

移除顺序：

1. Detection/input planner 先产出等价 `ArchiveInputDescriptor` 和 embedded inputs。
2. `ArchiveTask` 格式选择改读 canonical archive source/detection fields。
3. password resolver 不再依赖 `analysis.selected_format`。
4. Extraction 改读 input planner 的 canonical segment/input 字段。
5. 首次进入 repair 前调用 Inspect，补齐结构、损坏和 fuzzy evidence。
6. repair 后与候选状态刷新全部改用 Inspect。
7. 删除主流程 `analysis_stage.analyze_tasks(tasks)` 及相关 executor。

正常归档不进入 Inspect。Repair 首轮必须在 diagnosis/job 构造前获得 Inspection
feedback，否则旧主流程 Analysis 移除后会丢失 repair 所需结构证据。

## 第四阶段：兼容清理

- 删除 `ArchiveAnalysisStage`。
- 删除公开 `ArchiveAnalysisScheduler`，保留私有能力 engine。
- 删除 repair runtime 的 `getattr` 多入口兼容调用。
- 删除主流程 Analysis task/module 专用 executor。
- 将 repair 配置迁入 `inspect.*`，删除失效的主流程 Analysis 配置。
- CLI `inspect --analyze` 直接调用 `ArchiveAnalyzer`。
- repair 持久状态从 `analysis.*` 迁入 `inspection.*`；中性 `format.*` 保留。
- 删除旧字段双写、fallback 和 facade。
- 增加依赖边界测试，禁止 Analysis 导入 task/repair/inspect/coordinator。
- 更新文档、性能基线并重建知识图谱。

## 分段提交顺序

1. 冻结现状行为和依赖基线。
2. 建立 Inspect DTO/source/service，旧 stage 暂时委托。
3. 迁移 repair refresh 和 repair-training。
4. shadow 接入 beam candidate inspection，再单独启用排序反馈。
5. 拆分 knowledge/projector。
6. 迁移 segment -> `ArchiveInputDescriptor` 到 input planner。
7. Detection 与旧 stage 双跑比对。
8. 切换主流程输入规划并删除 `analyze_tasks`。
9. 收口 Analysis engine 和公共 API。
10. 删除兼容字段、配置、facade，完成全量回归。

## 每阶段验收

- Detection decision、score、matched rules 不变。
- task 数量、顺序、logical name 和 `ArchiveInputDescriptor` 不变。
- SFX、多 embedded、多卷、patched、password-required 和压缩 TAR 有覆盖。
- Repair 首轮 evidence 不少于旧 stage；candidate cache 必须包含 source identity、
  volume identity、patch digest 和 request fingerprint。
- Inspection 参与排序前保留 shadow 对比数据。
- ZIP/RAR/7z/TAR/压缩流不重新出现 Detection 私有解析实现。
- 运行针对性 unit/integration/performance tests、全量 tests 和 `git diff --check`。
- 删除旧入口前先审计所有 inbound callers 和持久字段消费者。

## 停止条件

遇到以下情况必须先调查，不得猜测或直接删除旧实现：

- Detection 输出或 ArchiveInput 构造发生无法解释的变化；
- single/multi-volume/patched source 对同一结构给出冲突结论；
- repair model 所需 raw format field 丢失；
- 完整校验被 header plausibility 替代；
- cache identity 无法区分不同 patch state；
- 读取量、候选量或并发开销出现数量级回退；
- 当前实现与格式规范冲突。

格式问题优先查阅 7-Zip 官方格式说明、RAR technote、PKWARE APPNOTE、相关 RFC、
POSIX/GNU TAR 文档或官方源码。第三方资料只能作为线索。

## 进度

- [x] 重构指导与最终边界确定。
- [x] 建立 Inspect 并迁移 repair-loop feedback。
- [x] 迁出 Analysis 业务调度、输入构造和知识投影。
- [x] 从主流程移除 Analysis。
- [x] 清理兼容、完成全量回归和知识图谱重建。

最终验收（2026-07-29）：Python 全量测试 `1009 passed, 71 skipped`，Rust native
测试 `77 passed`。知识图谱以 full 模式重建，并确认主流程从 Coordinator 进入
Detection/input planning，Inspect 的生产调用点位于 repair 前、候选评估和 repair 后。
