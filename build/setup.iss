[Setup]
AppName=Trels
AppVersion={#APP_VERSION}
AppPublisher=Trels Team
AppPublisherURL=https://github.com/txorav/trels
DefaultDirName={autopf}\Trels
DefaultGroupName=Trels
OutputDir=..\build\bin
OutputBaseFilename=trels-setup-{#ARCH}
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64 arm64
PrivilegesRequired=admin

[Files]
Source: "..\build\bin\trels.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Trels"; Filename: "{app}\trels.exe"
Name: "{group}\Uninstall Trels"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\trels.exe"; Description: "Launch Trels (Runs in background, open http://localhost:8080 or mapped domains)"; Flags: nowait postinstall
