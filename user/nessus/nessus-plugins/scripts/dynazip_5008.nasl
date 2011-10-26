#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22312);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(19143);

  script_name(english:"DynaZip Zip Archive Handling Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version of DynaZip's dzip32.dll / dzips32.dll");

  desc = "
Synopsis :

There is a library file installed on the remote Windows host that is
affected by several buffer overflow vulnerabilities. 

Description :

The version of the DynaZip Max or DynaZip Max Secure installed on the
remote host contains a DLL that reportedly is prone to stack-based
overflows when repairing or updating a specially-crafted ZIP file. 
Successful exploitation allows an attacker to execute arbitrary code
on the affected host subject to the user's privileges. 

Note that DynaZip libraries are included in some third-party
applications to provide support for handling ZIP files. 

See also :

http://vuln.sg/dynazip5007-en.html
http://www.securityfocus.com/archive/1/441083/30/0/threaded

Solution :

Either upgrade to DynaZip Max 5.0.0.8 / DynaZip Max Secure 6.0.0.5 or
later or contact the appropriate vendor for a fix. 

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";
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
include("smb_hotfixes_fcheck.inc");


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
  if (log_verbosity > 1) debug_print("can't connect to the remote registry!", level:0);
  NetUseDel();
  exit(0);
}


# Determine possible paths for the DLLs.
npaths = 0;
paths = make_array();
# - Windows system directories (DynaZip Max uses the SYSTEM32 directory)
sys_root = hotfix_get_systemroot();
if (sys_root)
{
  paths[npaths++] = sys_root + "\system";
  paths[npaths++] = sys_root + "\system32";
}
# - PowerArchiver
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\POWERARC.EXE";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item)) {
    path = item[1];
    path =  ereg_replace(pattern:'^(.+)\\POWERARC\\.EXE$', replace:"\1", string:path);
    paths[npaths++] = path;
  }
  RegCloseKey(handle:key_h);
}
# - TurboZIP
key = "SOFTWARE\FileStream.com\TurboZIP";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"Install Path");
  if (!isnull(item)) {
    path = item[1];
    paths[npaths++] = path;
  }
  RegCloseKey(handle:key_h);
}
key = "SOFTWARE\FileStream\TurboZIP Express";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item)) {
    path = item[1];
    paths[npaths++] = path;
  }
  RegCloseKey(handle:key_h);
}
if (!npaths)
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Check each path until we find an affected version.
vulnerable = 0;
for (i=0; i<npaths; i++)
{
  path = paths[i];
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);

  if (
    is_accessible_share(share:share) &&
    (
      hotfix_check_fversion(file:"dzip32.dll",  path:path, version:"5.0.0.8") == HCF_OLDER ||
      hotfix_check_fversion(file:"dzips32.dll", path:path, version:"6.0.0.5") == HCF_OLDER
    )
  )
  {
    vulnerable = 1;
    break;
  }
}
hotfix_check_fversion_end();


if (vulnerable) security_hole(port);
