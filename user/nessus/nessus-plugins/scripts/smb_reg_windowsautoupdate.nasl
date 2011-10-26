#
# (C) Tenable Network Security
#
#
# Thanks to Greg Hoglund <hoglund@hbgary.com> for suggesting this.
#

if(description)
{
 script_id(12028);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "WindowsUpdate disabled";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Remote system is not configured for automatic updates.

Description :

The remote host does not have Windows Update enabled. 

Enabling WindowsUpdate will ensure that the remote Windows host has
all the latest Microsoft Patches installed.

Solution : 

Enable Windows Update on this host

See also :

http://www.microsoft.com/security/protect/

Risk factor :

None / CVSS Base Score : 0 
(AV:L/AC:H/Au:R/C:N/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the value of AUState";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
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

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(0);
}


key = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update";
item = "AUState";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value) && (value[1] == 7))
   security_note (port);
 
 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();

