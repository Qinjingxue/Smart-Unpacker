Historical scoring rules moved out of the active rule package.

The active detection pipeline now uses `archive_identity` as the single scoring rule for magic-start archive evidence and embedded-archive evidence. These files are kept only as historical reference and are not imported by rule discovery.
