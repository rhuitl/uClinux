#
#  (C) Tenable Network Security
#


if (description)
{
  script_id(21749);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(18521);

  script_name(english:"WebWasher Remote ARJ Decoder Denial of Service Vulnerability");
  script_summary(english:"Checks version of WebWasher"); 
 
 desc = "
Synopsis :

The remote Windows host has an application that is suffers from a
denial of service vulnerability. 

Description :

According to its version, the version of WebWasher installed on the
remote host is affected by a denial of service overflow when handling
a specially-crafted ARJ file. 

Solution :

Upgrade to WebWasher 5.3.0 build 2252 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Get some info about the install.
path = NULL;
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Webwasher CSM";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"UninstallString");
  if (!isnull(item))
  {
    if ("\UNWISE" >< item[1])
      path = ereg_replace(pattern:"^([^ ]*)\\UNWISE\.EXE.*$", replace:"\1", string:item[1]);
  }

  RegCloseKey(handle:key_h);
}


# If it is...
if (path)
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\bin\WebWasherCSM.exe", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # There's a problem if the version is before 5.3.0.2252.
  if (!isnull(ver))
  {
    if (
      ver[0] < 5 ||
      (
        ver[0] == 5 && 
        (
          ver[1] < 3 ||
          (ver[1] == 3 && ver[2] == 0 && ver[3] < 2252)
        )
      )
    ) security_note(kb_smb_transport());
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
