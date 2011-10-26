#
#  (C) Tenable Network Security
#


if (description)
{
  script_id(21620);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-2439");
  script_bugtraq_id(18160);
  script_xref(name:"OSVDB", value:"25830");

  script_name(english:"ZipCentral Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of ZipCentral"); 
 
 desc = "
Synopsis :

The remote Windows host has an application that is suffers from a
buffer overflow vulnerability. 

Description :

According to its version, the ZipCentral program installed on the
remote host is affected by a stack-based buffer overflow when handling
a ZIP file with specially-crafted filenames. 

See also :

http://secunia.com/secunia_research/2006-35/advisory/

Solution :

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 1.8
(AV:R/AC:H/Au:NR/C:N/I:P/A:N/B:N)";
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
key = "SOFTWARE\ZipCentral";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
exe = NULL;
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Application Path");
  if (!isnull(item)) exe = item[1];

  RegCloseKey(handle:key_h);
}


# If it is...
if (exe)
{
  # Determine its version from the executable itself.
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

  # There's a problem if the version is 4.0.1.0 or earlier.
  if (!isnull(ver))
  {
    if (
      ver[0] < 4 ||
      (ver[0] == 4 && ver[1] == 0 && ver[2] <= 1)
    ) security_note(kb_smb_transport());
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
