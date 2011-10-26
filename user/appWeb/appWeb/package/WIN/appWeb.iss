;
; appWeb.iss -- Inno Setup 3 install configuration file for Mbedthis AppWeb
;
; Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
;

[Setup]
AppName=!!BLD_NAME!!
AppVerName=!!BLD_NAME!! !!BLD_VERSION!!-!!BLD_NUMBER!!
DefaultDirName=C:\appWeb
DefaultGroupName=!!BLD_NAME!!
UninstallDisplayIcon={app}\!!BLD_PRODUCT!!.exe
LicenseFile=./LICENSE.TXT

[Icons]
Name: "{group}\Mbedthis AppWeb"; Filename: "{app}\bin\winAppWeb.exe"
Name: "{group}\ReadMe"; Filename: "{app}\README.TXT"

[Registry]
;Root: HKLM; Subkey: "System\Current Control Set\Services\EventLog\Application\!!BLD_PRODUCT!!"; Flags: uninsdeletekeyifempty
;Root: HKCU; Subkey: "Software\!!BLD_COMPANY!!"; Flags: uninsdeletekeyifempty
;Root: HKCU; Subkey: "Software\!!BLD_COMPANY!!\Sample"; Flags: uninsdeletekey
;Root: HKLM; Subkey: "Software\!!BLD_COMPANY!!"; Flags: uninsdeletekeyifempty
;Root: HKLM; Subkey: "Software\!!BLD_COMPANY!!\Sample"; Flags: uninsdeletekey
;Root: HKLM; Subkey: "Software\!!BLD_COMPANY!!\Sample\Settings"; ValueType: string; ValueName: "Path"; ValueData: "{app}"

[Types]
Name: "full"; Description: "Complete Installation with Documentation and Samples"; 
Name: "binary"; Description: "Binary Installation"; 
Name: "documentation"; Description: "Documentation and Samples Installation"; 

[Components]
Name: "bin"; Description: "Binary Files"; Types: binary full;
Name: "doc"; Description: "Documentation Files"; Types: documentation full;

[Dirs]
Name: "{app}\logs"
Name: "{app}\bin"

[UninstallDelete]
Type: files; Name: "{app}\!!BLD_PRODUCT!!.conf";
Type: files; Name: "{app}\logs\access.log";
Type: files; Name: "{app}\logs\access.log.old";
Type: files; Name: "{app}\logs\error.log";
Type: files; Name: "{app}\logs\error.log.old";
Type: filesandordirs; Name: "{app}\*.obj";

[Code]
function IsDocInstalled(const file: String): Boolean;
begin
  if FileExists(file) then begin
    Result := True;
  end else begin
    Result := False;
  end
end;

[Run]
Filename: "{app}\bin\winAppWeb.exe"; Parameters: "-i -d"; WorkingDir: "{app}"; StatusMsg: "Installing AppWeb as a Windows Service"; Flags: waituntilidle
Filename: "{app}\bin\winAppWeb.exe"; Parameters: "-g"; WorkingDir: "{app}"; StatusMsg: "Starting the AppWeb Server"; Flags: waituntilidle
Filename: "http://127.0.0.1:7777/"; Description: "View the Documentation"; Flags: waituntilidle shellexec postinstall; Check: IsDocInstalled({app}\doc\index.html)

[UninstallRun]
Filename: "{app}\bin\winAppWeb.exe"; Parameters: "-u"; WorkingDir: "{app}"; Check: IsDocInstalled({app}\bin\winAppWeb.exe)
Filename: "{app}\remove.exe"; Parameters: "-r -s 5"; WorkingDir: "{app}"; Flags:

[Files]
