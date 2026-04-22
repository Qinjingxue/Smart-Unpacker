This directory only keeps small, redistributable test fixtures in Git.

Do not commit:
- real game archives
- copyrighted samples
- third-party binaries
- large generated archives used only for local validation

Private local-only samples can be placed in either of these locations:
- `fixtures/private/`
- `fixtures/samples/`

Current optional local sample paths used by tests:
- `fixtures/rpgmakertest.7z`
- `fixtures/samples/rpgmakertest.7z`

If the RPG Maker sample is missing, the semantic acceptance test is skipped instead of failing. This keeps the public repository reproducible without redistributing copyrighted content.
