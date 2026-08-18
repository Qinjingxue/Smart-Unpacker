#ifndef AppVersion
  #define AppVersion "dev"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\sunpack-x64-lite"
#endif
#ifndef OutputDir
  #define OutputDir "..\release"
#endif
#ifndef OutputBaseFilename
  #define OutputBaseFilename "sunpack-windows-setup"
#endif
#ifndef TargetArch
  #define TargetArch "x64"
#endif
#ifndef RepairSystem
  #define RepairSystem "lite"
#endif

[Setup]
AppId={{9E8C73E5-C540-4E68-93E0-1FBAAFB89713}
AppName=SunPack
AppVersion={#AppVersion}
AppVerName=SunPack {#AppVersion} ({#TargetArch}, {#RepairSystem})
AppPublisher=SunPack
DefaultDirName={localappdata}\Programs\SunPack
DefaultGroupName=SunPack
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseFilename}
SetupIconFile={#SourceDir}\sunpack.ico
UninstallDisplayIcon={app}\sunpack.ico
LicenseFile=..\LICENSE
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
ChangesAssociations=yes
CloseApplications=yes
RestartApplications=no
UsePreviousAppDir=yes
UsePreviousTasks=yes

#if TargetArch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Add SunPack to the current user's PATH"; GroupDescription: "Shell integration:"
Name: "contextmenu"; Description: "Register the SunPack folder context menu"; GroupDescription: "Shell integration:"
Name: "autostart"; Description: "Start SunPack Watch when Windows starts"; GroupDescription: "Background watch:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "sunpack_watch_roots.txt,builtin_passwords.txt"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\sunpack_watch_roots.txt"; DestDir: "{app}"; Flags: onlyifdoesntexist skipifsourcedoesntexist
Source: "{#SourceDir}\builtin_passwords.txt"; DestDir: "{app}"; Flags: onlyifdoesntexist skipifsourcedoesntexist

[UninstallDelete]
Type: filesandordirs; Name: "{app}\*"
Type: dirifempty; Name: "{app}"
Type: filesandordirs; Name: "{localappdata}\SunPack"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SunPackWatchService"; ValueData: """{app}\sunpack-watch.exe"""; Tasks: autostart; Flags: uninsdeletevalue

[Icons]
Name: "{group}\SunPack Command Prompt"; Filename: "{cmd}"; Parameters: "/K cd /D ""{app}"""; WorkingDir: "{app}"; IconFilename: "{app}\sunpack.ico"
Name: "{group}\Uninstall SunPack"; Filename: "{uninstallexe}"

[Code]
const
  SunPackRegistryKey = 'Software\SunPack';
  EnvironmentRegistryKey = 'Environment';
  StartupRegistryKey = 'Software\Microsoft\Windows\CurrentVersion\Run';
  StartupValueName = 'SunPackWatchService';
  PathMarkerName = 'PathAddedByInstaller';

function NormalizePathEntry(Value: string): string;
begin
  Value := Trim(Value);
  if (Length(Value) >= 2) and (Value[1] = '"') and (Value[Length(Value)] = '"') then
    Value := Copy(Value, 2, Length(Value) - 2);
  while (Length(Value) > 3) and ((Value[Length(Value)] = '\') or (Value[Length(Value)] = '/')) do
    Delete(Value, Length(Value), 1);
  Result := Lowercase(Value);
end;

function PopPathEntry(var Remaining: string): string;
var
  Separator: Integer;
begin
  Separator := Pos(';', Remaining);
  if Separator = 0 then
  begin
    Result := Remaining;
    Remaining := '';
  end
  else
  begin
    Result := Copy(Remaining, 1, Separator - 1);
    Delete(Remaining, 1, Separator);
  end;
end;

function PathContains(const PathValue, Entry: string): Boolean;
var
  Remaining: string;
  Token: string;
  NormalizedEntry: string;
begin
  Result := False;
  Remaining := PathValue;
  NormalizedEntry := NormalizePathEntry(Entry);
  while Remaining <> '' do
  begin
    Token := PopPathEntry(Remaining);
    if NormalizePathEntry(Token) = NormalizedEntry then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

procedure AddUserPath;
var
  CurrentPath: string;
  AppPath: string;
  NewPath: string;
begin
  AppPath := ExpandConstant('{app}');
  if not RegQueryStringValue(HKCU, EnvironmentRegistryKey, 'Path', CurrentPath) then
    CurrentPath := '';
  if PathContains(CurrentPath, AppPath) then
    Exit;
  NewPath := CurrentPath;
  if (NewPath <> '') and (NewPath[Length(NewPath)] <> ';') then
    NewPath := NewPath + ';';
  NewPath := NewPath + AppPath;
  if RegWriteExpandStringValue(HKCU, EnvironmentRegistryKey, 'Path', NewPath) then
    RegWriteDWordValue(HKCU, SunPackRegistryKey, PathMarkerName, 1);
end;

procedure RemoveUserPath;
var
  WasAdded: Cardinal;
  CurrentPath: string;
  Remaining: string;
  Token: string;
  NewPath: string;
  AppPath: string;
begin
  if not RegQueryDWordValue(HKCU, SunPackRegistryKey, PathMarkerName, WasAdded) or (WasAdded <> 1) then
    Exit;
  if not RegQueryStringValue(HKCU, EnvironmentRegistryKey, 'Path', CurrentPath) then
    CurrentPath := '';
  Remaining := CurrentPath;
  AppPath := NormalizePathEntry(ExpandConstant('{app}'));
  NewPath := '';
  while Remaining <> '' do
  begin
    Token := PopPathEntry(Remaining);
    if (Trim(Token) <> '') and (NormalizePathEntry(Token) <> AppPath) then
    begin
      if NewPath <> '' then
        NewPath := NewPath + ';';
      NewPath := NewPath + Trim(Token);
    end;
  end;
  RegWriteExpandStringValue(HKCU, EnvironmentRegistryKey, 'Path', NewPath);
  RegDeleteValue(HKCU, SunPackRegistryKey, PathMarkerName);
  RegDeleteKeyIfEmpty(HKCU, SunPackRegistryKey);
end;

procedure RemoveStartupRunValue;
begin
  RegDeleteValue(HKCU, StartupRegistryKey, StartupValueName);
end;

function PowerShellSingleQuotedString(Value: string): string;
begin
  StringChangeEx(Value, '''', '''''', True);
  Result := '''' + Value + '''';
end;

procedure RunContextMenuScript(RegisterMenu: Boolean);
var
  PowerShellPath: string;
  ScriptPath: string;
  Parameters: string;
  ResultCode: Integer;
begin
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  if RegisterMenu then
  begin
    ScriptPath := ExpandConstant('{app}\scripts\register_context_menu.ps1');
    Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
      AddQuotes(ScriptPath) + ' -AppPath ' + AddQuotes(ExpandConstant('{app}\sunpack.exe')) +
      ' -IconPath ' + AddQuotes(ExpandConstant('{app}\sunpack.ico'));
  end
  else
  begin
    ScriptPath := ExpandConstant('{app}\scripts\unregister_context_menu.ps1');
    Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + AddQuotes(ScriptPath);
  end;
  if not FileExists(ScriptPath) then
  begin
    Log('Context menu script was not found: ' + ScriptPath);
    Exit;
  end;
  if not Exec(PowerShellPath, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Failed to start context menu script: ' + ScriptPath)
  else if ResultCode <> 0 then
    Log(Format('Context menu script exited with code %d: %s', [ResultCode, ScriptPath]));
end;

procedure StopExistingWatch;
var
  ExistingApp: string;
  ResultCode: Integer;
begin
  ExistingApp := ExpandConstant('{app}\sunpack.exe');
  if not FileExists(ExistingApp) then
    Exit;
  if not Exec(ExistingApp, 'watch stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Failed to start existing SunPack watch stop command: ' + ExistingApp)
  else if ResultCode <> 0 then
    Log(Format('Existing SunPack watch stop command exited with code %d', [ResultCode]));
  if not Exec(ExistingApp, '--persistent-shutdown', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Failed to stop existing SunPack persistent process: ' + ExistingApp)
  else if ResultCode <> 0 then
    Log(Format('Existing SunPack persistent shutdown exited with code %d', [ResultCode]));
end;

function WaitForExistingWatchToExit: Boolean;
var
  PowerShellPath: string;
  CliAppPath: string;
  WatchAppPath: string;
  Command: string;
  Parameters: string;
  ResultCode: Integer;
begin
  Result := True;
  CliAppPath := ExpandConstant('{app}\sunpack.exe');
  WatchAppPath := ExpandConstant('{app}\sunpack-watch.exe');
  if (not FileExists(CliAppPath)) and (not FileExists(WatchAppPath)) then
    Exit;
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Command :=
    '$targets = @(' + PowerShellSingleQuotedString(CliAppPath) + ', ' + PowerShellSingleQuotedString(WatchAppPath) + '); ' +
    '$deadline = (Get-Date).AddSeconds(20); ' +
    'do { ' +
    '  $running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { ' +
    '    try { $processPath = [System.IO.Path]::GetFullPath($_.Path); @($targets | Where-Object { [System.IO.Path]::GetFullPath($_).Equals($processPath, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0 } catch { $false } ' +
    '  }); ' +
    '  if ($running.Count -eq 0) { exit 0 }; ' +
    '  Start-Sleep -Milliseconds 250; ' +
    '} while ((Get-Date) -lt $deadline); ' +
    'exit 1';
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ' + AddQuotes(Command);
  if not Exec(PowerShellPath, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Log('Failed to wait for existing SunPack watch process to exit.');
    Result := False;
  end
  else if ResultCode <> 0 then
  begin
    Log(Format('Timed out waiting for existing SunPack watch process to exit: %d', [ResultCode]));
    Result := False;
  end;
end;

function StopExistingWatchAndWait: Boolean;
begin
  StopExistingWatch;
  Result := WaitForExistingWatchToExit;
end;

function IsPersistentInstallFile(const FileName: string): Boolean;
begin
  Result :=
    (CompareText(FileName, 'sunpack_watch_roots.txt') = 0) or
    (CompareText(FileName, 'builtin_passwords.txt') = 0);
end;

function ClearInstallDirectory: Boolean;
var
  AppPath: string;
  SearchPath: string;
  ItemPath: string;
  FindData: TFindRec;
begin
  Result := True;
  AppPath := ExpandConstant('{app}');
  if not DirExists(AppPath) then
    Exit;

  SearchPath := AddBackslash(AppPath) + '*';
  if not FindFirst(SearchPath, FindData) then
    Exit;
  try
    repeat
      if (FindData.Name <> '.') and (FindData.Name <> '..') then
      begin
        ItemPath := AddBackslash(AppPath) + FindData.Name;
        if DirExists(ItemPath) then
        begin
          if not DelTree(ItemPath, True, True, True) and DirExists(ItemPath) then
          begin
            Log('Failed to remove old SunPack directory: ' + ItemPath);
            Result := False;
          end;
        end
        else if not IsPersistentInstallFile(FindData.Name) then
        begin
          if not DeleteFile(ItemPath) and FileExists(ItemPath) then
          begin
            Log('Failed to remove old SunPack file: ' + ItemPath);
            Result := False;
          end;
        end;
      end;
    until not FindNext(FindData);
  finally
    FindClose(FindData);
  end;
end;

function ClearExternalRuntimeState: Boolean;
var
  StateRoot: string;
begin
  StateRoot := ExpandConstant('{localappdata}\SunPack');
  if not DirExists(StateRoot) then
  begin
    Result := True;
    Exit;
  end;
  Result := DelTree(StateRoot, True, True, True) or not DirExists(StateRoot);
  if not Result then
    Log('Failed to remove old SunPack external runtime state: ' + StateRoot);
end;

procedure InitializeWizard();
begin
  WizardForm.LicenseAcceptedRadio.Checked := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  if not StopExistingWatchAndWait then
  begin
    Result := 'SunPack Watch is still running. Please stop it and run the installer again.';
    Exit;
  end;
  RunContextMenuScript(False);
  RemoveStartupRunValue;
  RemoveUserPath;
  if not ClearInstallDirectory then
  begin
    Result := 'Some old SunPack files could not be removed. Close SunPack and run the installer again.';
    Exit;
  end;
  if not ClearExternalRuntimeState then
  begin
    Result := 'Some old SunPack runtime state could not be removed. Close SunPack and run the installer again.';
    Exit;
  end;
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  RemoveStartupRunValue;
  Result := StopExistingWatchAndWait;
  if not Result then
    MsgBox('SunPack Watch is still running. Please stop it and run the uninstaller again.', mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('addtopath') then
      AddUserPath;
    if WizardIsTaskSelected('contextmenu') then
      RunContextMenuScript(True)
    else
      RunContextMenuScript(False);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    RunContextMenuScript(False);
    RemoveStartupRunValue;
    RemoveUserPath;
  end;
end;
