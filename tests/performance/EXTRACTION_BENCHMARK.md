# Extraction format benchmark

Run `.venv\\Scripts\\python.exe tests/performance/extract_format_benchmark.py --runs 3 --json-out build/extraction-benchmark.json`.

The generated corpus covers ZIP, 7z, split 7z, TAR, gzip, bzip2, xz, and their
tar aliases for both many-small-file and few-large-file workloads. Supply formats that 7-Zip cannot create:
`--sample rar=C:\corpus\sample.rar --sample zst=C:\corpus\sample.zst`.
Missing `.rar`, `.Z`, `.zst`, and `.tzst` inputs are reported as skipped rather
than silently reducing coverage. Run outputs are deleted between samples.

Detection is warmed up and timed in-process, so Python startup and CLI rendering
are not counted as detection work. Raw 7-Zip time is reported as the backend
baseline. To compare detection against another revision, create a Git worktree
and pass it with `--compare-root`; each revision then scans the exact same corpus.
Comparison mode uses ABBA revision order and reports the median of `2 * --runs`
detection samples to reduce cache, CPU-frequency, and run-order bias:

```powershell
git worktree add ..\sunpack-before-refactor 0bb6d15
.venv\Scripts\python.exe tests/performance/extract_format_benchmark.py `
  --compare-root ..\sunpack-before-refactor --runs 5 `
  --json-out build\extraction-benchmark.json
```

Use at least five runs for regression decisions. Close CPU-heavy applications,
keep the corpus on the same disk, and compare the aggregate detection delta as
well as individual formats. A one-run invocation with smaller payloads is only
a compatibility smoke test.
