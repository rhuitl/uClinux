#
# (C) Tenable Network Security
#


if (description) {
  script_id(20804);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-0337", "CVE-2006-0338");
  script_bugtraq_id(16309);
  script_xref(name:"OSVDB", value:"22632");
  script_xref(name:"OSVDB", value:"22633");

  script_name(english:"F-Secure ZIP/RAR Archive Handling Overflow Vulnerabilities");
  script_summary(english:"Checks for ZIP/RAR archive handling overflow vulnerabilities in F-Secure products");
 
  desc = "
Synopsis :

The remote anti-virus software is affected by multiple buffer overflow
vulnerabilities

Description :

The remote host is running an anti-virus software application from
F-Secure. 

The version of F-Secure anti-virus installed on the remote Windows
host contains flaws in the way it handles ZIP and RAR archives that
reportedly can be leveraged by an attacker to bypass scanning or to
execute arbitrary code remotely subject to the local SYSTEM
privileges. 

See also :

http://www.zoller.lu/
http://www.f-secure.com/security/fsc-2006-1.shtml

Solution :

Enable auto-updates if using F-Secure Internet Security 2004-2006,
F-Secure Anti-Virus 2004-2006, or F-Secure Personal Express version
6.20 or earlier.  Otherwise, apply the appropriate hotfix as listed in
the vendor advisory referenced above. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

name    = kb_smb_name();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  exit(0);
}

path = NULL;

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
 NetUseDel();
 exit (0);
}

key[0] = "SOFTWARE\Data Fellows\F-Secure\Anti-Virus";
key[1] = "SOFTWARE\Data Fellows\F-Secure\Content Scanner Server";

item = "Path";

for (i=0; i<max_index(key); i++)
{
 hkey = RegOpenKey(handle:hklm, key:key[i], mode:MAXIMUM_ALLOWED);
 if (!isnull(hkey))
 {
  value = RegQueryValue(handle:hkey, item:item);
  if (!isnull(value))
    path[i] = value[1];

  RegCloseKey (handle:hkey);
 }
 else
   path[i] = NULL;
}

RegCloseKey (handle:hklm);
NetUseDel ();


vulnerable = FALSE;

for (i=0; i<max_index(path); i++)
{
 if (!isnull(path[i]) && is_accessible_share())
 {
  if ( hotfix_check_fversion(file:"fm4av.dll", version:"1.6.34.90", path:path[i]) == HCF_OLDER )
    vulnerable = TRUE;
  else if ( hotfix_check_fversion(file:"fslfpi.dll", version:"2.3.8.0", path:path[i]) == HCF_OLDER )
    vulnerable = TRUE;

  hotfix_check_fversion_end();
  if (vulnerable == TRUE)
    break;
 }
}

if (vulnerable == TRUE)
  security_warning(port);
