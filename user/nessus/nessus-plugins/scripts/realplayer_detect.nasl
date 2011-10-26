#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote Windows host has a media player installed on it. 

Description :

This script detects whether the remote Windows host is running
RealPlayer / RealOne Player / RealPlayer Enterprise and, if so,
extracts its version number. 

RealPlayer is a media player from RealNetworks. 

See also :

http://www.real.com/

Risk factor : 

None";


if (description) {
  script_id(20183);
  script_version("$Revision: 1.3 $");

  script_name(english:"RealPlayer Detection");
  script_summary(english:"Detects RealPlayer");
 
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


# nb: RealPlayer and RealOne Player record the installed version number
#     in HKEY_LOCAL_MACHINE\SOFTWARE\RealNetworks\RealPlayer\version
#     but don't seem to remove that if the software is removed. Also,
#     RealPlayer Enterprise puts it version number in, eg, 
#     HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RealPlayer Enterprise 6.0\UninstallString


# Connect to the remote registry.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(1);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1);
session_init(socket:soc, hostname:name);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(1);
}


# Figure out where the executable is.
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\RealPlay.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (isnull(key_h)) {
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}

value = RegQueryValue(handle:key_h, item:"Path");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if (isnull(value)) {
  NetUseDel();
  exit(0);
}
path = value[1];


# Get the file version from the executable itself.
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\realplay.exe", string:path);
NetUseDel(close:FALSE);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (r != 1) {
  NetUseDel();
  exit(1);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh)) {
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# If the version number's available, save and report it.
if (!isnull(ver)) {
  version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

  set_kb_item(name:"SMB/RealPlayer/Version", value: version);

    # nb: there's no good way to discover which RealPlayer this is.
    #     The default install path, though, does include the name; eg,
    #       C:\Program Files\Real\RealOne Player\realplay.exe
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Version ", version, " of RealPlayer is installed as:\n",
      "  ", path, "\\realplay.exe\n"
    );
    security_note(port:port, data:report);
}
