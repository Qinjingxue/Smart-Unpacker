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
    assert "function ClearInstallDirectory: Boolean" in script
    assert "function ClearExternalRuntimeState: Boolean" in script
    assert "IsPersistentInstallFile" in script
    assert "FindData: TFindRec" in script
    assert "DirExists(ItemPath)" in script
    assert "TFindData" not in script
    assert "sunpack_watch_roots.txt,builtin_passwords.txt" in script
    assert 'Source: "{#SourceDir}\\sunpack_watch_roots.txt"; DestDir: "{app}"; Flags: onlyifdoesntexist skipifsourcedoesntexist' in script
    assert 'Source: "{#SourceDir}\\builtin_passwords.txt"; DestDir: "{app}"; Flags: onlyifdoesntexist skipifsourcedoesntexist' in script
    assert "RunContextMenuScript(False);" in script
    assert "RemoveStartupRunValue;" in script
    assert "RemoveUserPath;" in script


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
    assert 'Type: filesandordirs; Name: "{app}\\*"' in script
    assert 'Type: dirifempty; Name: "{app}"' in script
    assert 'Type: filesandordirs; Name: "{localappdata}\\SunPack"' in script


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
    assert "-RequireInstaller" in build_script
    assert "RequireInstaller = $true" in workflow
    assert "test_windows_installer.ps1" in workflow
    assert "Expected four lite release files" in workflow
    assert "*-setup.exe" in workflow


def test_local_build_falls_back_to_portable_zip_when_inno_is_missing():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")

    assert "if ($RequireInstaller)" in build_script
    assert "Continuing with the portable ZIP only" in build_script
    assert "$SkipInstaller = $true" in build_script
    assert "-SkipInstaller and -RequireInstaller cannot be used together" in build_script


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


def test_lite_build_excludes_model_runtime_from_shared_environment():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")

    assert '"zstandard"' in build_script
    assert '"--nofollow-import-to=$package"' in build_script
    assert "Assert-LitePackageExcludesModelRuntime -PackageRoot $distAppRoot" in build_script


def test_build_uses_nuitka_only():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "Packager" not in build_script
    assert "PyInstaller" not in build_script
    assert not (ROOT / "SunPack.spec").exists()
    assert '"-m", "nuitka"' in build_script
    assert '"--standalone"' in build_script
    assert '"--windows-console-mode=$ConsoleMode"' in build_script
    assert '"--lto=yes"' in build_script
    assert '"--pgo-c"' in build_script
    assert '"--pgo-args=$PgoArgs"' in build_script
    assert '-PgoArgs "--help"' in build_script
    assert '-PgoArgs "--once --no-tray"' in build_script
    assert 'Remove-IfExists -LiteralPath (Join-Path $nuitkaWatchDist ".sunpack_watch")' in build_script
    assert 'Embed-WindowsApplicationManifest -PythonPath $venvPython' in build_script
    assert '"scripts\\embed_windows_manifest.py"' in build_script
    assert '"--nofollow-import-to=$package"' in build_script
    assert "Invoke-NuitkaStandaloneBuild" in build_script
    assert '"sunpack.repair.model.policy"' in build_script
    assert "sunpack.detection.pipeline.rules.hard_stop" not in build_script
    assert "sunpack.detection.pipeline.rules.confirmation" not in build_script
    assert '"nuitka>=2"' in project
    assert "pyinstaller" not in project.lower()


def test_runtime_bootstrap_emits_startup_diagnostics_without_polluting_watch():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")

    assert "EnableStartupDiagnostics" in build_script
    assert "faulthandler.dump_traceback_later(5, repeat=True, file=sys.stderr)" in build_script
    assert build_script.count("-EnableStartupDiagnostics") == 1


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

    assert 'Join-Path $installRoot "builtin_passwords.txt"' in script
    assert 'Join-Path $installRoot ".sunpack_watch"' in script
    assert 'Join-Path $env:LOCALAPPDATA "SunPack\\cache"' in script
    assert "Upgrade install overwrote the existing builtin password file" in script
    assert "Upgrade install left stale application data behind" in script
    assert "Upgrade install left stale configuration data behind" in script
    assert "Set-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName" in script
    assert "Uninstaller left the watch state directory behind" in script
    assert "Uninstaller left the local SunPack cache behind" in script


def test_release_packages_copy_only_runtime_tool_files():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts" / "verify_windows_package_arch.ps1").read_text(encoding="utf-8")

    for script in (build_script, verifier):
        assert "function Get-PackagedRuntimeToolNames" in script
        assert '"7z.dll"' in script
        assert '"sunpack_sevenzip.dll"' in script
        assert '"sunpack_sevenzip_worker.exe"' in script
        assert "Assert-PackagedRuntimeTools" in script
    assert "Copy-PackagedRuntimeTools -Source $toolsRoot -Destination $distToolsRoot" in build_script
    assert 'Assert-PathMissing -LiteralPath (Join-Path $distAppRoot "zstandard")' in build_script
    assert 'Copy-Item -LiteralPath $toolsRoot -Destination $distToolsRoot -Recurse -Force' not in build_script


def test_release_packages_exclude_test_only_python_runtime():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '"zstandard",' in build_script
    assert '"--nofollow-import-to=$package"' in build_script
    assert 'if ($repairSystemMode -eq "lite")' in build_script
    assert 'Assert-PathMissing -LiteralPath (Join-Path $distAppRoot "zstandard")' in build_script
    assert '"zstandard>=0.22.0"' not in project.split("[project.optional-dependencies]", 1)[0]
    assert '"zstandard>=0.22.0"' in project


def test_acceptance_setup_bootstraps_and_checks_real_archive_generators():
    setup_script = (ROOT / "scripts" / "setup_windows_dev.ps1").read_text(encoding="utf-8")
    acceptance_script = (ROOT / "run_acceptance_tests.ps1").read_text(encoding="utf-8")

    assert ".sunpack_test_tools" in setup_script
    assert "winrar-x64-622.exe" in setup_script
    assert "zstd-v1.5.7-win64.zip" in setup_script
    assert "Test-RarGeneratorVersion" in setup_script
    assert "SkipAcceptanceTestTools" in setup_script
    assert "Assert-AcceptanceTestTools" in acceptance_script
    assert "Default.SFX" in acceptance_script
    assert "zstd.exe" in acceptance_script


def test_release_package_includes_console_and_gui_executables():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")

    assert '$watchExeName = "sunpack-watch.exe"' in build_script
    assert "Packaged SunPack watch GUI executable" in build_script
    assert 'ConsoleMode "force"' in build_script
    assert 'ConsoleMode "disable"' in build_script
