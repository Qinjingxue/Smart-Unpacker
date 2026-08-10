# Watch validation

`tests/integration/watch_validation.py` exercises the real Windows observer, NTFS file identity/USN probes,
adaptive quiet policy, and exclusive-readiness gate. It does not run extraction; each candidate
declared ready is validated as a complete ZIP instead.

The default matrix covers atomic moves, timestamp-preserving copies, slow append downloads,
close/reopen writers, preallocated and parallel range writes, browser temporary names, aria2
sidecars, a long network pause, timestamp restoration, same-size writes with fixed mtime, an open
writer handle, and a 5,000-event storm.

Run both permission modes from a normal terminal:

```powershell
.\.venv\Scripts\python.exe tests\integration\watch_validation.py `
  --mode matrix `
  --output .sunpack_watch_validation\latest
```

The command first runs normally, then displays one UAC prompt for the elevated child. Rejecting
the prompt leaves `elevated_launched` false in `matrix.json`; the non-elevated report is still
complete. Individual scenarios can be selected with repeated `--scenario NAME` arguments.
Pass `--resume` with a single-mode report to keep passing scenarios and rerun only failures.

Each JSON and Markdown report records final readiness, ZIP validity, premature and temporary-file
attempts, post-write stability latency, observed filesystem events, native observation cost, USN
Reason availability, CPU time, peak RSS growth, and event-storm throughput.
