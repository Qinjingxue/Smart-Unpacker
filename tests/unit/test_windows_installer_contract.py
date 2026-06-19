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
