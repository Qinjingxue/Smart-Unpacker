# Extraction format benchmark

Run `python tests/performance/extract_format_benchmark.py --runs 3 --json-out build/extraction-benchmark.json`.

The generated corpus covers ZIP, 7z, TAR, gzip, bzip2, xz, their tar aliases,
7z volumes, and a many-small-files ZIP. Supply formats that 7-Zip cannot create:
`--sample rar=C:\corpus\sample.rar --sample zst=C:\corpus\sample.zst`.
Missing `.rar`, `.Z`, `.zst`, and `.tzst` inputs are reported as skipped rather
than silently reducing coverage. Run outputs are deleted between samples.

Subprocess startup and detection are measured independently. Raw 7-Zip time is
also reported as the backend baseline. Internal stages that cannot be isolated
without changing production scheduling are emitted as `null`; their combined
in-process pipeline time remains available, so the report never invents phase
precision from overlapping subprocess measurements.
