#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote Windows host has an application that is susceptible to
multiple heap overflow attacks. 

Description :

The Windows remote host contains Backup Exec for Windows Server /
Backup Exec Continuous Protection Server, a commercial backup product. 

The version of the software installed on the remote host reportedly
contains several heap overflows involving specially-crafted calls to
its RPC interfaces.  Exploitation of these issues may allow a remote
attacker with authorized but non-privileged access to crash the
affected application and possibly to execute arbitrary code and gain
elevated privileges on the affected host. 

See also :

http://www.symantec.com/avcenter/security/Content/2006.08.11.html

Solution :

Apply the appropriate hotfix as listed in the vendor advisory
referenced above. 

Risk factor : 

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22226);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4128");
  script_bugtraq_id(19479);

  script_name(english:"Symantec Backup Exec Multiple Heap Overflow Vulnerabilities");
  script_summary(english:"Checks for version of Symantec Backup Exec"); 
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
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


# Get paths where the affected files are installed.
paths = NULL;
npaths = 0;
#
# - Backup Exec CPS
key = "SOFTWARE\VERITAS\Backup Exec CPS";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ENLSharedPath");
  if (!isnull(value)) paths[npaths++] = value[1];

  RegCloseKey(handle:key_h);
}
# - Backup Exec
key = "SOFTWARE\VERITAS\Backup Exec\Install";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; ++i) {
    value = RegEnumValue(handle:key_h, index:i);
    if (!isnull(value))
    {
      subkey = value[1];
      if (strlen(subkey) && subkey =~ "^Path [0-9]")
      {
        # Get the install path.
        value = RegQueryValue(handle:key_h, item:subkey);
        if (!isnull(value)) paths[npaths++] = value[1];
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();
if (!npaths) exit(0);


# Check the version.
for (i=0; i<=npaths; i++)
{
  path = paths[i];
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  if (is_accessible_share(share:share))
  {
    if (
      hotfix_check_fversion(file:"beremote.exe", path:path, version:"10.1.5629.34", min_version:"10.1.5629.0") == HCF_OLDER ||
      hotfix_check_fversion(file:"beremote.exe", path:path, version:"10.0.5520.32", min_version:"10.0.5520.0") == HCF_OLDER ||
      hotfix_check_fversion(file:"beremote.exe", path:path, version:"10.0.5484.36", min_version:"10.0.5484.0") == HCF_OLDER ||
      hotfix_check_fversion(file:"beremote.exe", path:path, version:"9.1.4691.58", min_version:"9.1.4691.0") == HCF_OLDER ||
      hotfix_check_fversion(file:"rxservice.exe", path:path, version:"10.1.327.901", min_version:"10.1.325.0") == HCF_OLDER
    ) security_warning(port);
  }
  hotfix_check_fversion_end();
}
