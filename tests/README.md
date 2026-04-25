# Test Layout

The suite is organized by how tests grow:

- `cases/`: JSON data cases. Add ordinary CLI, detection, and postprocess scenarios here first.
- `runners/`: Generic pytest runners for files in `cases/`. These should change rarely.
- `helpers/`: Shared builders, assertions, config factories, and CLI helpers.
- `unit/`: Focused module and contract tests with no end-to-end pipeline behavior.
- `functional/`: Cross-module behavior tests that still avoid real external extraction when possible.
- `integration/`: Pipeline, extraction, and execution-path tests.
- `performance/`: Lightweight pressure and concurrency behavior tests.
- `cli/`: CLI parser, command contract, and CLI command behavior tests.

Prefer adding a JSON case before adding a new Python test file. Add a Python test when a new runner, helper, or genuinely new interaction is needed.

`tests/integration/test_real_archive_edge_cases.py` keeps a fast real-archive smoke set enabled by default and marks the full format matrix as `slow_real_archive`.
Run the full matrix explicitly with:

```powershell
pytest tests/integration/test_real_archive_edge_cases.py --run-slow-real-archives
```
