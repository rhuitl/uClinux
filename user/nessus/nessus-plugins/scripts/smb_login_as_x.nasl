#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14818);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0028");
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0200");
 name["english"] = "Possible GDI+ compromise";
  
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to log into the remote host with the login 'X' and
a blank password.

A widely available exploit, using one of the vulnerabilities described
in the Microsoft Bulletin MS04-028 creates such an account. This probably
mean that the remote host has been compromised by the use of this exploit.

See also : http://www.microsoft.com/technet/security/Bulletin/MS04-028.mspx
Solution : Re-install this host, as it has been compromised
Risk factor : Critical";

 script_description(english:desc["english"]);
 
 summary["english"] = "Logs in as user 'X' with no password";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_login.nasl");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

login = "X";
pass  = "";

if(get_kb_item("SMB/any_login"))exit(0);


port = kb_smb_transport(); 
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login + string(rand()), password:pass + string(rand()), domain:NULL, share:"IPC$");
NetUseDel();
if ( r == 1 )  exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:NULL, share:"IPC$");
if ( r == 1 ) security_hole(port);
NetUseDel();
