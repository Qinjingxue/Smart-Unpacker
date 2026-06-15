# 模型运行时与训练边界

SunPack 的模型代码分成正式运行时和训练工具两层。

## 正式运行时

`sunpack/model_runtime/` 随源码包和 Windows 发行包分发，包含：

- diagnosis 图 schema、ZIP 图构建和校验
- diagnosis HGT model、tensorize 和 inference
- repair policy transformer schema、model、tensorize 和 inference
- `ModelAssetRegistry`
- 内置 diagnosis 与 policy provider

`sunpack/repair` 只通过内置 provider 调用模型。运行时不扫描 Python 包、不读取 `repair_training/runs`，也不接受 `provider_package` 配置。

## 模型资产

所有正式资产位于：

```text
models/
  manifest.json
  zip/
    diagnosis_hgt/
    repair_policy_transformer/
```

manifest 是唯一入口。`packaged_path` 必须位于 `models/` 内，`sha256` 必须匹配该模型目录中的 `model.pt`。源码运行和 PyInstaller 发行包使用同一目录结构。

检查资产与加载能力：

```powershell
python sunpack.py models status --json
python sunpack.py models status --load --json
```

## 推理链路

```text
verification requests repair
  -> RepairScheduler
  -> RepairPolicyManager
  -> DiagnosisHGTProvider
  -> diagnosis graph + root-case scores
  -> enumerate module / undo / stop actions
  -> RepairPolicyTransformerProvider
  -> ranked actions + predicted next state
  -> materialize selected action
  -> extraction
  -> verification
```

模型输出是决策建议，不是成功判定。真实产物必须经过 extraction 和 verification。

## 训练工具

`repair_training/` 负责：

- 训练材料与损坏样本生成
- diagnosis/policy dataset 构建
- model training 和搜索
- runtime profile、A/B 和一致性评估
- run 目录管理

训练代码复用 `sunpack.model_runtime` 的 model、schema 和 tensorize 实现，确保训练与生产推理一致。依赖方向只能是：

```text
repair_training -> sunpack.model_runtime
```

禁止：

```text
sunpack.model_runtime -> repair_training
```

## 发布新模型

1. 在 `repair_training` 中完成训练与评估。
2. 将选定模型的完整运行时资产复制到 `models/<format>/<role>/`。
3. 计算 `model.pt` SHA-256。
4. 更新 `models/manifest.json` 的语义、算法、路径和哈希。
5. 运行 `python sunpack.py models status --load --json`。
6. 执行模型运行时测试和 Windows 完整构建。

不要在构建脚本中写死训练 run 路径，也不要为实验模型增加动态 provider 兼容层。
