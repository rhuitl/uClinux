#
#  (C) Tenable Network Security
#


if (description) {
  script_id(21340);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2304");
  script_bugtraq_id(17931);
  script_xref(name:"OSVDB", value:"25429");

  script_name(english:"Novell Client Buffer Overflow");
  script_summary(english:"Checks file version of dprpcw32.dll"); 
 
 desc = "
Synopsis :

The remote Windows host contains a DLL that suffers from a buffer
overflow flaw. 

Description :

The file 'dprpcw32.dll' included with the Novell Client software
reportedly contains a potential buffer overflow. 

See also :

http://support.novell.com/cgi-bin/search/searchtid.cgi?/2973719.htm

Solution :

Install the 491psp2_dprpcw32.exe beta patch file referenced in the
vendor advisory above. 

Risk factor :

High / CVSS Base Score : 9.9
(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)";
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
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Unless we're being paranoid, check whether the software's installed.
if (report_paranoia < 2)
{
  subkey = "{Novell Client for Windows}";
  key = string("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/", subkey, "/DisplayName");
  if (isnull(get_kb_item(key))) exit(0);
}


# Connect to the appropriate share.
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
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Check the version of dprpcw32.dll.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:winroot);
dll =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\System32\dprpcw32.dll", string:winroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1) {
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh)) {
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  # nb: for older versions, the file version will be null.
  if (isnull(ver)) security_hole(get_kb_item("SMB/transport"));
  else if (
    # nb: version of the patch is 3.0.2.0.
    int(ver[0]) < 3 ||
    (int(ver[0]) == 3 && int(ver[1]) == 0 && int(ver[2]) < 2)
  ) security_hole(get_kb_item("SMB/transport"));
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
