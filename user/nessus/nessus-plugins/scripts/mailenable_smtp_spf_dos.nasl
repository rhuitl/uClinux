#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22411);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4616");
  script_bugtraq_id(20091);

  script_name(english:"MailEnable SMTP Connector Service SPF Record Denial of Service Vulnerability");
  script_summary(english:"Checks version of MailEnable's MESMTPC.exe");

  desc = "
Synopsis :

The remote SMTP server is affected by a denial of service flaw. 

Description :

The remote host is running MailEnable, a commercial mail server for
Windows. 

The SMTP server bundled with the version of MailEnable installed on
the remote host reportedly suffers from a flaw in which SPF lookups
for domains with large records may result in a null pointer exception
in the SMTP service.  An unauthenticated remote attacker may be able
to exploit this issue to crash the affected service. 

See also :

http://www.mailenable.com/hotfix/

Solution :

Apply Hotfix ME-10014. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smtpserver_detect.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports("Services/smtp", 25, 139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smtp_func.inc");


smtp_port = get_kb_item("Services/smtp");
if (!smtp_port) port = 25;
if (!get_port_state(smtp_port)) exit(0);
if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);


# Make sure the banner corresponds to MailEnable.
banner = get_smtp_banner(port:smtp_port);
if (
  !banner ||
  !egrep(pattern:"Mail(Enable| Enable SMTP) Service", string:banner)
) exit(0);


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


# Determine location of MailEnable's application directory.
path = NULL;
key = "SOFTWARE\Mail Enable\Mail Enable";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"Application Directory");
  if (!isnull(item)) path = item[1];
  RegCloseKey(handle:key_h);
}
if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Check version of MESMTPC.exe
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\MESMTPC.exe", string:path);

if (
  is_accessible_share(share:share) &&
  hotfix_check_fversion(file:"MESMTPC.exe",  path:path, version:"1.0.0.20") == HCF_OLDER
) security_note(smtp_port);

hotfix_check_fversion_end();
