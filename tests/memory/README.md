# Watch 内存增长测试

运行长期、大量文件的 watch 内存测试：

```powershell
.\.venv\Scripts\python.exe -m pytest --run-performance -s tests/memory/test_watch_growth.py
```

测试默认处理 4 批、每批 2 个 64 MiB 归档；归档内容采用流式生成，不会因为构造测试文件而额外占用同等 Python 内存。可用环境变量缩放测试：

- `SUNPACK_WATCH_MEMORY_BATCHES`
- `SUNPACK_WATCH_MEMORY_FILES_PER_BATCH`
- `SUNPACK_WATCH_MEMORY_PAYLOAD_MIB`
- `SUNPACK_WATCH_MEMORY_PAYLOAD_KIB`
- `SUNPACK_WATCH_MEMORY_INTERVAL_SECONDS`
- `SUNPACK_WATCH_MEMORY_TIMEOUT_SECONDS`
- `SUNPACK_WATCH_MEMORY_MAX_SLOPE_MIB_PER_FILE`
- `SUNPACK_WATCH_MEMORY_MAX_ACTIVE_PIPELINES`（Windows 输出提升出现瞬态访问冲突时可设为 `1`）
- `SUNPACK_WATCH_MEMORY_TRACEMALLOC=1`

每次运行会在 pytest 的临时目录生成 `watch-memory-report.json`。报告包含每个批次的 RSS、worker RSS、watch 状态规模、队列计数，以及全局缓存、reader cache、projection cache、archive session、关系探测密码缓存、修复检查缓存和持久 worker pool 的快照。
