#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

 desc["english"] = "
Synopsis :

Access the remote Windows Registry.

Description :

It was possible to access the remote Windows Registry using the login
/ password combination used for the Windows local checks (SMB tests).

Risk factor :

None";

 desc_bad["english"] = "
Synopsis :

Access the remote Windows Registry.

Description :

It was not possible to connect to PIPE\winreg on the remote host.
If you intend to use Nessus to perform registry-based checks, the
registry checks will not work because the 'Remote Registry Access'
service (winreg) has been disabled on the remote host or can not be
connected to with the supplied credentials.

Risk factor :

None";


if(description)
{
 script_id(10400);
 script_version ("$Revision: 1.30 $");
 #script_bugtraq_id(6830);
 #script_cve_id("CVE-1999-0562");
 
 name["english"] = "SMB accessible registry";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the remote registry is accessible";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_exclude_keys("SMB/samba");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

logged = 0;

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r == 1 )
{
 hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if (! isnull(hklm) ) 
 {
  RegCloseKey (handle:hklm);
  logged = 1;
 }
 NetUseDel();
}

if (logged == 0)
{
 security_note (port:port, data:desc_bad["english"]);
}
else
{
 security_note (port);

 set_kb_item(name:"SMB/registry_access", value:TRUE);
}
