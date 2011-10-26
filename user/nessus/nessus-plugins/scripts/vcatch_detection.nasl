#
# Copyright (C) 2004 Tenable Network Security 
#
#

if(description)
{
 script_id(12004);
 script_version("$Revision: 1.4 $");
 name["english"] = "VCATCH detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the VCATCH program.  
You should ensure that:
- the user intended to install VCATCH (it is sometimes silently installed)
- the use of VCATCH matches your corporate mandates and security policies.

To remove this sort of software, you may wish to check out ad-aware or spybot. 

See also : http://www.safersite.com/PestInfo/v/vcatch_3_0.asp 

Solution : Uninstall this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "VCATCH detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_registry_full_access.nasl");
 script_require_keys("SMB/registry_full_access");

 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

# start the script
if ( ! get_kb_item("SMB/registry_full_access") ) exit(0);

path[0] = "software\microsoft\windows\currentversion\app management\arpcache\vcatch - the personal virus catcher";
path[1] = "software\microsoft\windows\currentversion\uninstall\vcatch - the personal virus catcher";

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


key = "Software\Microsoft\Windows NT\WinLogon";
item = "DontDisplayLastUserName";

for (i=0; path[i]; i++)
{
 key_h = RegOpenKey(handle:hklm, key:path[i], mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
 {
  security_hole(port);
  RegCloseKey(handle:key_h);
  break;
 } 
}

RegCloseKey(handle:hklm);
NetUseDel();

