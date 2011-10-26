#
# (C) Tenable Network Security
#


if (description) {
  script_id(19703);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2957");
  script_bugtraq_id(14824);

  name["english"] = "AVIRA Desktop for Windows ACE Archive Handling Buffer Overflow Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote Windows host contains an application that is affected by a
buffer overflow. 

Description :

The remote host is running AVIRA Desktop for Windows. 

The installed version of AVIRA Desktop for Windows is reportedly prone
to a stack-based buffer overflow when scanning ACE archives with long
filenames.  An attacker can exploit this issue to execute arbitrary
code on the remote host. 

See also : 

http://secunia.com/secunia_research/2005-43/advisory/

Solution : 

Upgrade AVPACK32.DLL to version 6.31.1.7 or later via online update.

Risk factor : 

High / CVSS Base Score : 8
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for ACE archive handling buffer overflow vulnerability in AVIRA Desktop for Windows";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);
name = kb_smb_name();
port = kb_smb_transport();
if (!get_port_state(port)) exit(0);
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.
soc = open_sock_tcp(port);
if (!soc) exit(0);
session_init(socket:soc, hostname:name);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(1);
}


# Get the software's installation directory from the registry.
key = "SOFTWARE\AVIRA GmbH\AVIRA Desktop";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
dir = NULL;
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"AVWPath");
  if (!isnull(value)) dir = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


# If it's installed...
if (dir) {
  # Read version / build info directly from the affected DLL.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dir);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(1);
  }

  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dir);
  file = string(file, "\\AVPack32.dll");
  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  ver = GetFileVersion(handle:fh);

  # There's a problem if it's earlier than version 6.31.1.7.
  if (!isnull(ver)) {
    if (
      (ver[0] < 6) ||
      (ver[0] == 6 && ver[1] < 31) ||
      (ver[0] == 6 && ver[1] == 31 && ver[2] < 1) ||
      (ver[0] == 6 && ver[1] == 31 && ver[2] == 1 && ver[3] < 7)
    ) security_hole(0);
  }
}


# Clean up.
NetUseDel();
