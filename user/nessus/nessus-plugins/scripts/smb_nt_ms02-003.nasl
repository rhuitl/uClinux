#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(11309);
 script_bugtraq_id(4053);
 script_version("$Revision: 1.11 $");
 
 script_cve_id("CVE-2002-0049");
 
 name["english"] = "Winreg registry key writeable by non-admins";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Local users can elevate their privileges.

Description :

The key HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg 
is writeable by non-administrators.

The installation software of Microsoft Exchange sets this key to
a world-writeable mode.

Local users may use this misconfiguration to escalate their privileges on 
this host.

Solution : 

Microsoft has released a set of patches for the Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-003.mspx

Risk factor : 

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the permissions for the winreg key";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_full_access.nasl",
 		     "smb_reg_service_pack.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access");
 script_require_ports(139, 445);
 script_require_keys("SMB/WindowsVersion");
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

key = "SYSTEM\CurrentControlSet\Control\SecurePipeServers\WinReg";

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
