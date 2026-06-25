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
    assert 'ValueData: """{app}\\sunpack.exe"" watch start"' in script
    assert "Tasks: autostart" in script
    assert "uninsdeletevalue" in script


def test_installer_stops_existing_watch_before_upgrade_and_cleans_owned_files():
    script = (ROOT / "installer" / "SunPack.iss").read_text(encoding="utf-8")

    assert "procedure StopExistingWatch" in script
    assert "watch stop" in script
    assert "function PrepareToInstall" in script
    assert "StopExistingWatch;" in script
    assert "[InstallDelete]" in script
    assert 'Type: files; Name: "{app}\\*.exe"' in script
    assert 'Type: filesandordirs; Name: "{app}\\sunpack"' in script
    assert 'Type: filesandordirs; Name: "{app}\\tools"' in script
    assert 'Type: files; Name: "{app}\\*.json"' not in script
    assert 'Type: files; Name: "{app}\\*.txt"' not in script


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


def test_installer_smoke_uses_process_exit_code_not_last_exit_code():
    script = (ROOT / "scripts" / "test_windows_installer.ps1").read_text(encoding="utf-8")

    assert "Start-Process" in script
    assert "-PassThru" in script
    assert "$process.ExitCode" in script
    assert "$LASTEXITCODE" not in script


def test_release_packages_exclude_build_only_7z_executable():
    build_script = (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts" / "verify_windows_package_arch.ps1").read_text(encoding="utf-8")

    assert '$packagedSevenZipExe = Join-Path $distToolsRoot "7z.exe"' in build_script
    assert "Remove-Item -LiteralPath $packagedSevenZipExe" in build_script
    assert 'Assert-PathMissing -LiteralPath (Join-Path $distToolsRoot "7z.exe")' in build_script
    assert 'Assert-PathMissing -LiteralPath (Join-Path $root "tools\\7z.exe")' in verifier
