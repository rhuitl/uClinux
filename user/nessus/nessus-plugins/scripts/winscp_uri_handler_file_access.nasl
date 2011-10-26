#
#  (C) Tenable Network Security
#


if (description)
{
  script_id(21737);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-3015");
  script_bugtraq_id(18384);

  script_name(english:"WinSCP URI Handler File Access Vulnerability");
  script_summary(english:"Checks version of WinSCP"); 
 
 desc = "
Synopsis :

The remote Windows host has an application that allows arbitrary file
access. 

Description :

According to its version, the WinSCP program installed on the remote
host may allow a remote attacker to automatically initiate a file
transfer to or from the affected host or to append log information to
an existing file, provided the user can be tricked into clicking on a
malicious link. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-June/046810.html
http://winscp.net/eng/docs/history#3.8.2

Solution :

Upgrade to WinSCP version 3.8.2 or later.

Risk factor : 

Low / CVSS Base Score : 3.6
(AV:R/AC:H/Au:NR/C:P/I:P/A:N/B:N)";
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
exe = NULL;
foreach handler (make_list("SCP", "SFTP"))
{
  key = "SOFTWARE\Classes\" + handler + "\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item)) exe = item[1];

    RegCloseKey(handle:key_h);
  }
  if (!isnull(exe)) break;
}


# If it is...
if (exe)
{
  # Determine its version from the executable itself.
  exe = ereg_replace(pattern:'^"(.+)".*$', replace:"\1", string:exe);

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exe);
  exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exe);
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

  # There's a problem if the version is before 3.8.2.
  if (!isnull(ver))
  {
    if (
      ver[0] < 3 ||
      (
        ver[0] == 3 && 
        (
          ver[1] < 8 ||
          (ver[1] == 8 && ver[2] < 2)
        )
      )
    ) security_note(kb_smb_transport());
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
