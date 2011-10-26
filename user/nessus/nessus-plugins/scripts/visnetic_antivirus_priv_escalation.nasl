#
# (C) Tenable Network Security
#


if (description) {
  script_id(20993);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2006-0812");
  script_bugtraq_id(16788);

  script_name(english:"Visnetic AntiVirus Plug-in for MailServer Local Privilege Escalation Vulnerability");
  script_summary(english:"Checks version of Visnetic AntiVirus Plug-in for MailServer");
 
  desc = "
Synopsis :

The remote Windows application is prone to a local privilege
escalation issue. 

Description :

The version of VisNetic AntiVirus Plug-in for MailServer installed on
the remote host does not drop its privileges before invoking other
programs.  An attacker with local access can exploit this flaw to
execute arbitrary programs on the affected host with LOCAL SYSTEM
privileges. 

See also :

http://secunia.com/secunia_research/2005-65/advisory/

Solution :

Upgrade to VisNetic AntiVirus Plug-in for VisNetic MailServer version
4.6.1.2 or later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain root remotely");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
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
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  #if (log_verbosity > 1) debug_print("can't connect to the remote registry!", level:0);
  NetUseDel();
  exit(0);
}


# Determine which version of VisNetic's AntiVirus Plug-in is installed.
key = "SOFTWARE\Deerfield.com\VisNetic AntiVirus\Plug-in\Updates";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(value)) {
    ver = value[1];
    # There's a problem if it's < 4.6.1.2.
    if (ver && ver =~ "^([0-3]\.|4\.([0-5]\.|6\.(0\.|1\.[01])))") {
      security_hole(port);
    }
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# Clean up.
NetUseDel();
