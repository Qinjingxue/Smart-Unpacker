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
Name: "autostart"; Description: "Start SunPack Watch when Windows starts"; GroupDescription: "Background watch:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
Type: files; Name: "{app}\*.pyd"
Type: files; Name: "{app}\*.dll"
Type: files; Name: "{app}\*.exe"
Type: files; Name: "{app}\*.manifest"
Type: files; Name: "{app}\*.ico"
Type: files; Name: "{app}\*.py"
Type: filesandordirs; Name: "{app}\_internal"
Type: filesandordirs; Name: "{app}\analysis"
Type: filesandordirs; Name: "{app}\config"
Type: filesandordirs; Name: "{app}\licenses"
Type: filesandordirs; Name: "{app}\models"
Type: filesandordirs; Name: "{app}\native"
Type: filesandordirs; Name: "{app}\scripts"
Type: filesandordirs; Name: "{app}\sunpack"
Type: filesandordirs; Name: "{app}\tools"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SunPackWatchService"; ValueData: """{app}\sunpack.exe"" watch start"; Tasks: autostart; Flags: uninsdeletevalue

[Icons]
Name: "{group}\SunPack Command Prompt"; Filename: "{cmd}"; Parameters: "/K cd /D ""{app}"""; WorkingDir: "{app}"; IconFilename: "{app}\sunpack.ico"
Name: "{group}\Uninstall SunPack"; Filename: "{uninstallexe}"

[Code]
const
  SunPackRegistryKey = 'Software\SunPack';
  EnvironmentRegistryKey = 'Environment';
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
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopExistingWatch;
  Result := '';
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
    RemoveUserPath;
  end;
end;
