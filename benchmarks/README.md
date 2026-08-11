# Performance benchmarks

Performance measurements and diagnostic profiles live here; behavioural assertions live under `tests/`.

List the supported scenarios:

```powershell
python -m benchmarks --list
```

Run a scenario by group and name. Arguments after the scenario are passed to that scenario:

```powershell
python -m benchmarks reader password-fast-path --rounds 5
python -m benchmarks reader volume-anchor --files 128 --logical-mib 64 --rounds 5
python -m benchmarks scan hotspots . --mode full --json-out build/scan-hotspots.json
python -m benchmarks extraction format-matrix --runs 5 --json-out build/extraction-benchmark.json
python -m benchmarks extraction split-pressure --profile acceptance --strict
python -m benchmarks memory residual-rss
```

## Real archive workspace lifecycle

Scenarios that generate real archives use `BenchmarkWorkspace` and share this lifecycle:

1. Create corpus, work, and extraction-output directories under `build/benchmark-tmp/`.
2. Generate archives through the existing `ArchiveFixtureFactory` or scenario corpus builder.
3. Always write `report.json` and `manifest.json` under
   `build/benchmark-results/<scenario>/<UTC timestamp>-<run id>/`.
4. Remove the complete temporary work directory when the scenario exits, including on failure.

Use `--results-root PATH` to put durable results elsewhere. Use `--keep-workdir` only when
debugging a generated archive; the retained path is recorded in `manifest.json`. Temporary
archives are never copied to the durable result directory implicitly, so large corpora do not
accumulate. A scenario may explicitly preserve a small diagnostic artifact with the workspace API.

`extraction format-matrix` builds ZIP, 7z, split 7z, RAR, split RAR, TAR, gzip,
bzip2, xz, zstd, Unix compress and the conventional compressed-TAR aliases. It uses
the bundled binaries under `tools/`; the test-only Unix-compress fixture builder lives
under `benchmarks/tools/`. Each archive is placed in an isolated scanner input directory,
then both SunPack's complete detection/extraction flow and raw 7-Zip are timed. Only cases
whose extracted payload hashes pass on both sides contribute to the comparison ratio.
The matrix starts extractor commands strictly one at a time and adds a short cooldown
between invocations, while leaving SunPack's internal scheduler at its program-controlled
default and using unlimited recursive extraction. Generated scanner entry files are
rejected when they fall below the project's 1 MiB recognition floor.

The reusable harness in `benchmarks/harness` defines the common wall/CPU clocks,
process-tree memory sampling, real-archive workspace lifecycle, and versioned JSON report
envelope. New scenarios must use those components instead of adding another local timer,
RSS sampler, or temporary-directory policy.

The following obsolete probes were intentionally removed during consolidation:

- cache saturation and idle-thread scripts that inspected `_ENGINE`, `_runtime`, and `_SESSIONS`;
- the standalone scan-layer probe, subsumed by `scan hotspots --mode ...`;
- the hard-coded nested-authorization microbenchmark;
- the PowerShell memory stress script;
- the separate SunPack-versus-7-Zip runner, subsumed by the format matrix baseline.

Use pytest only for stable product contracts. Opt-in timing/resource assertions are
marked `performance` and run with `pytest --run-performance`; multi-GB resource-guard
tests additionally require `--run-large-archive-performance`.
