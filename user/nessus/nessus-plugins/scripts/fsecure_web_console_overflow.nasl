#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote Windows host has an application that is vulnerable to a
buffer overflow. 

Description :

The remote host is running an anti-virus software application from
F-Secure. 

The Windows remote host contains a version of F-Secure Internet
Gatekeeper and/or F-Secure Anti-Virus for Microsoft Exchange that is
affected by a buffer overflow in its web console that can be exploited
without any authentication. 

By default, the web console accepts connections only from the local
host so this issue can be exploited remotely only if the web console
has been specifically configured to accept connections remotely. 

See also :

http://www.f-secure.com/security/fsc-2006-3.shtml

Solution :

Upgrade / apply the appropriate hotfix as described in the vendor
advisory above. 

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


if (description)
{
  script_id(21644);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(18201);

  script_name(english:"F-Secure Web Console Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of F-Secure Web Console"); 
 
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
if (rc != 1) exit(0);


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Determine which F-Secure products are installed.
key = "SOFTWARE\Data Fellows\F-Secure";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i) {
    prod = RegEnumKey(handle:key_h, index:i);
    if (strlen(prod)) prods[prod]++;
  }
  RegCloseKey(handle:key_h);
}


# Determine the path to Web Console if an affected product is installed.
if (
  prods["Web User Interface"] &&
  (
    prods["Anti-Virus Agent for Microsoft Exchange"] ||
    prods["Anti-Virus for Internet Gateways"]
  )
)
{
  key = "SOFTWARE\Data Fellows\F-Secure\Web User Interface";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  path = NULL;
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Path");
    if (!isnull(value)) path = value[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
NetUseDel();
if (isnull(path)) exit(0);


# Check the version.
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
if (is_accessible_share(share:share))
{
  path += "bin";

  fixed = NULL;
  if (prods["Anti-Virus for Internet Gateways"]) fixed = "1.3.37.0";
  else if (prods["Anti-Virus Agent for Microsoft Exchange"]) fixed = "1.2.144.0";

  if (
    fixed &&
    hotfix_check_fversion(file:"fswebuid.exe", version:fixed, path:path) == HCF_OLDER
  ) security_hole(port);

  hotfix_check_fversion_end();
}
