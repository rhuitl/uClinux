#
# (C) Tenable Network Security
#
if(description)
{
 script_id(11867);
 script_bugtraq_id(2065);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2001-0047");

 name["english"] = "SMB Registry : permissions of the Microsoft Transaction Server key";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can gain additional privileges.

Description :

The registry key HKLM\SOFTWARE\Microsoft\Transaction Server\Packages
can be modified by users not in the admin group.

Write access to this key allows an unprivileged user to gain additional 
privileges.

See also :

http://www.microsoft.com/technet/security/bulletin/ms00-095.mspx

Solution : 

Use regedt32 and set the permissions of this key to :

- admin group  : Full Control
- system       : Full Control
- everyone     : Read
	
Risk factor : 

Medium / CVSS Base Score : 5 
(AV:L/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the access rights of a remote key";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

access = get_kb_item("SMB/registry_access");
if(!access)exit(0);

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

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(0);
}

key = "SOFTWARE\Microsoft\Transaction Server\Packages";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY); 
if(!isnull(key_h))
{
 rep = RegGetKeySecurity (handle:key_h, type: DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION);
 if(!isnull(rep) && registry_key_writeable_by_non_admin(security_descriptor:rep))
 {
   security_hole (port);
 }
 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel();
