#
#  (C) Tenable Network Security
#


if (description)
{
  script_id(21567);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-2173");
  script_bugtraq_id(17802);

  script_name(english:"FileZilla Server Interface Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of FileZilla Server Interface"); 
 
 desc = "
Synopsis :

The remote Windows host has an application that is suffers from a
buffer overflow vulnerability. 

Description :

According to its version, the FileZilla Server Interface installed on
the remote host is affected by an unspecified buffer overflow
vulnerability, which could be leveraged by an attacker to execute
arbitrary code subject to the privileges of the user running the
affected application. 

Note that to successfully exploit this remotely, the application would
need to be configured to accept remote connections, which it does not by
default.

See also :

http://www.securityfocus.com/archive/1/433251/30/0/threaded
http://filezilla.sourceforge.net/forum/viewtopic.php?t=2255
http://sourceforge.net/forum/forum.php?forum_id=569148

Solution :

Upgrade to FileZilla Server version 0.9.17 or later. 

Risk factor : 

Medium / CVSS Base Score : 4.6
(AV:R/AC:L/Au:NR/C:N/I:P/A:P/B:N)";
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
key = "SOFTWARE\FileZilla Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
path = NULL;
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Install_Dir");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}


# If it is...
if (path)
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\FileZilla Server Interface.exe", string:path);
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

  # There's a problem if the version is < 0.9.17.
  if (!isnull(ver))
  {
    if (
      ver[0] == 0 && 
      (
        ver[1] < 9 ||
        (ver[1] == 9 && ver[2] < 17)
      )
    ) security_warning(kb_smb_transport());
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
