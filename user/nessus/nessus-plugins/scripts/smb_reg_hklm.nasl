#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(10427);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0589");
 name["english"] = "SMB Registry : permissions of HKLM";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

System settings are writable by non admin.

Descirption :

The registry key HKEY_LOCAL_MACHINE is writeable by users who 
are not in the admin group.

This allows these users to create a lot of keys on that machine,
thus they can probably to get admin easily.

Such a configuration probably means that the system has been 
compromised.

Solution : 

use regedt32 and set the permissions of this key to :

- admin group  : Full Control
- system       : Full Control
- everyone     : Read
	
Risk factor :

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the access rights of a remote key";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
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

rep = RegGetKeySecurity (handle:hklm, type: DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION);
if(!isnull(rep) && registry_key_writeable_by_non_admin(security_descriptor:rep))
{
  security_hole (port);
}

RegCloseKey (handle:hklm);
NetUseDel();
