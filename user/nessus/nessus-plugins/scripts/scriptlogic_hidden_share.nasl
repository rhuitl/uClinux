#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11561);
 script_cve_id("CVE-2003-1122");
 script_bugtraq_id(7476);
 script_version ("$Revision: 1.7 $");
 name["english"] = "ScriptLogic logging share";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has an accessible LOGS$ share. 

ScriptLogic creates this share to store the logs, but does
not properly set the permissions on it. As a result, anyone can
use it to read the remote logs.

Solution : Limit access to this share to the backup account
and domain administrator.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Connects to LOG$";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");


port = kb_smb_transport();
name = kb_smb_name();
if(!name)exit(0);


login = kb_smb_login();
pass = kb_smb_password();
dom = kb_smb_domain();



if(!get_port_state(port))exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:dom, share:"LOG$");
if ( r != 1 ) exit(1);

handle = FindFirstFile (pattern:"\*");
if ( ! isnull(handle) ) security_hole(port);
NetUseDel();
