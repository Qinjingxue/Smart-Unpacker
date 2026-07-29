from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_installer_is_per_user_and_owns_only_its_path_entry():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "PrivilegesRequired=lowest" in script
    assert "DefaultDirName={localappdata}\\Programs\\SunPack" in script
    assert "PathAddedByInstaller" in script
    assert "procedure AddUserPath" in script
    assert "procedure RemoveUserPath" in script
    assert "RegQueryDWordValue" in script


def test_installer_registers_and_unregisters_context_menu():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "register_context_menu.ps1" in script
    assert "unregister_context_menu.ps1" in script
    assert "WizardIsTaskSelected('contextmenu')" in script
    assert "CurUninstallStepChanged" in script


def test_installer_optionally_registers_watch_autostart():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert 'Name: "autostart"' in script
    assert "Start SunPack Watch when Windows starts" in script
    assert "Software\\Microsoft\\Windows\\CurrentVersion\\Run" in script
    assert 'ValueName: "SunPackWatchService"' in script
    assert 'ValueData: """{app}\\sunpack-watch.exe"""' in script
    assert "Tasks: autostart" in script
    assert "uninsdeletevalue" in script


def test_uninstaller_unconditionally_removes_watch_autostart():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "StartupRegistryKey = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'" in script
    assert "StartupValueName = 'SunPackWatchService'" in script
    assert "procedure RemoveStartupRunValue" in script
    assert "RegDeleteValue(HKCU, StartupRegistryKey, StartupValueName)" in script
    assert "RemoveStartupRunValue;" in script


def test_installer_stops_existing_watch_before_upgrade_and_cleans_owned_files():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "procedure StopExistingWatch" in script
    assert "watch stop" in script
    assert "function PrepareToInstall" in script
    assert "StopExistingWatch;" in script
    assert "[InstallDelete]" in script
    assert 'Excludes: "sunpack_watch_roots.txt"' in script
    assert 'Source: "{#SourceDir}\\sunpack_watch_roots.txt"; DestDir: "{app}"; Flags: onlyifdoesntexist skipifsourcedoesntexist' in script
    assert 'Type: files; Name: "{app}\\*.exe"' in script
    assert 'Type: filesandordirs; Name: "{app}\\sunpack"' in script
    assert 'Type: filesandordirs; Name: "{app}\\tools"' in script
    assert 'Type: files; Name: "{app}\\*.json"' not in script
    assert 'Type: files; Name: "{app}\\*.txt"' not in script


def test_uninstaller_stops_running_watch_before_removing_files():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "function InitializeUninstall(): Boolean" in script
    assert "function WaitForExistingWatchToExit: Boolean" in script
    assert "function StopExistingWatchAndWait: Boolean" in script
    assert "RemoveStartupRunValue;" in script
    assert "Result := StopExistingWatchAndWait;" in script
    assert "Please stop it and run the uninstaller again." in script
    assert "Get-Process -ErrorAction SilentlyContinue" in script
    assert "WatchAppPath := ExpandConstant('{app}\\sunpack-watch.exe')" in script
    assert "$targets = @(" in script
    assert "CliAppPath: string;" in script
    assert "WatchAppPath: string;" in script
    assert "ExpandConstant('{app}\\sunpack.exe')" in script
    assert "$deadline = (Get-Date).AddSeconds(20)" in script
    assert "Start-Sleep -Milliseconds 250" in script


def test_uninstaller_removes_generated_watch_and_cache_state():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "[UninstallDelete]" in script
    assert 'Type: filesandordirs; Name: "{app}\\.sunpack_watch"' in script
    assert 'Type: files; Name: "{app}\\sunpack_watch_roots.txt"' in script
    assert 'Type: dirifempty; Name: "{app}"' in script
    assert 'Type: filesandordirs; Name: "{localappdata}\\SunPack\\cache"' in script
    assert 'Type: dirifempty; Name: "{localappdata}\\SunPack"' in script


def test_installer_declares_x64_and_arm64_modes():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert 'TargetArch == "arm64"' in script
    assert "ArchitecturesAllowed=arm64" in script
    assert "ArchitecturesAllowed=x64compatible" in script


def test_build_and_release_workflow_publish_portable_and_setup_packages():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "-setup.exe" in build_script
    assert "Get-InnoSetupCompiler" in build_script
    assert "test_windows_installer.ps1" in workflow
    assert "Expected four lite release files" in workflow
    assert "*-setup.exe" in workflow


def test_build_notes_handles_recreated_tags_and_noninteractive_log_output():
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "git fetch --force --prune --tags" in workflow
    assert '--exclude="${current_tag}"' in workflow
    assert 'commits="$(git log --format=\'- %s (%h)\' "${range}")"' in workflow
    assert 'if [ -n "${commits}" ]; then' in workflow
    assert "grep -q" not in workflow


def test_build_passes_edition_and_architecture_to_acceptance_setup():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    acceptance_script = (ROOT / "run_acceptance_tests.ps1").read_text(encoding="utf-8")

    assert '"-Arch", $buildArch' in build_script
    assert '"-RepairSystem", $repairSystemMode' in build_script
    assert '[string]$RepairSystem = "full"' in acceptance_script
    assert '"-RepairSystem", $RepairSystem' in acceptance_script


def test_windows_scripts_share_one_virtual_environment():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    setup_script = (ROOT / "scripts" / "setup_windows_dev.ps1").read_text(encoding="utf-8")

    assert ".venv-build" not in build_script
    assert 'Join-Path $repoRoot ".venv"' in build_script
    assert 'Join-Path $repoRoot ".venv"' in setup_script
    assert "IncludeBuildDeps" not in setup_script
    assert "$repoRoot[dev]" in build_script
    assert "$repoRoot[dev]" in setup_script
    assert 'Install-ModelRuntimeDependencies -PythonPath $venvPython' in build_script
    assert 'Install-ModelRuntimeDependencies -PythonPath $venvPython' in setup_script
    assert "Skipping model runtime dependencies" not in build_script
    assert "Skipping model runtime dependencies" not in setup_script


def test_lite_build_excludes_model_runtime_from_shared_environment():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    spec = (ROOT / "SunPack.spec").read_text(encoding="utf-8")

    assert 'model_runtime_excludes = ["torch", "torch_geometric", "torchgen", "functorch"]' in spec
    assert "excludes=[] if include_repair_models else model_runtime_excludes" in spec
    assert "Assert-LitePackageExcludesModelRuntime -PackageRoot $distAppRoot" in build_script


def test_windows_native_smoke_checks_follow_current_embedded_scan_api():
    smoke_scripts = (
        ROOT / "scripts" / "build_windows.ps1",
        ROOT / "scripts" / "setup_windows_dev.ps1",
        ROOT / "run_acceptance_tests.ps1",
    )

    for path in smoke_scripts:
        script = path.read_text(encoding="utf-8")
        assert "'scan_embedded_archives'" in script, path
        assert "'scan_carrier_archive'" not in script, path
        assert "'scan_directory_entries'" not in script, path


def test_installer_smoke_uses_process_exit_code_not_last_exit_code():
    script = (ROOT / "scripts" / "test_windows_installer.ps1").read_text(encoding="utf-8")

    assert "Start-Process" in script
    assert "-PassThru" in script
    assert "$process.ExitCode" in script
    assert "$LASTEXITCODE" not in script


def test_installer_smoke_exercises_generated_uninstall_residue_cleanup():
    script = (ROOT / "scripts" / "test_windows_installer.ps1").read_text(encoding="utf-8")

    assert 'Join-Path $installRoot ".sunpack_watch"' in script
    assert 'Join-Path $env:LOCALAPPDATA "SunPack\\cache"' in script
    assert "Set-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName" in script
    assert "Uninstaller left the watch state directory behind" in script
    assert "Uninstaller left the local SunPack cache behind" in script


def test_release_packages_exclude_build_only_7z_executable():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts" / "verify_windows_package_arch.ps1").read_text(encoding="utf-8")

    assert '$packagedSevenZipExe = Join-Path $distToolsRoot "7z.exe"' in build_script
    assert "Remove-Item -LiteralPath $packagedSevenZipExe" in build_script
    assert 'Assert-PathMissing -LiteralPath (Join-Path $distToolsRoot "7z.exe")' in build_script
    assert 'Assert-PathMissing -LiteralPath (Join-Path $root "tools\\7z.exe")' in verifier


def test_release_package_includes_console_and_gui_executables():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    spec = (ROOT / "SunPack.spec").read_text(encoding="utf-8")

    assert '$watchExeName = "sunpack-watch.exe"' in build_script
    assert "Packaged SunPack watch GUI executable" in build_script
    assert "console=False" in spec
    assert "watch_exe" in spec
