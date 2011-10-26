#
# Copyright (C) 2004 Tenable Network Security 
#
#

if(description)
{
 script_id(12001);
 script_version("$Revision: 1.4 $");

 name["english"] = "SaveNOW detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the SaveNOW program.  
You should ensure that:
- the user intended to install SaveNOW (it is sometimes silently installed)
- the use of SaveNOW matches your corporate mandates and security policies.

To remove this sort of software, you may wish to check
out ad-aware or spybot. 

Solution : Uninstall this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "SaveNOW detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

path[0] = "software\whenusave";
path[1] = "software\Microsoft\Windows\CurrentVersion\WhenUSave";
path[2] = "software\classes\clsid\{08351226-6472-43bd-8a40-d9221ff1c4ce}";
path[3] = "software\classes\clsid\{9f95f736-0f62-4214-a4b4-caa6738d4c07}";
path[4] = "software\classes\interface\{c285d18d-43a2-4aef-83fb-bf280e660a97}";
path[5] = "software\microsoft\windows\currentversion\uninstall\savenow";


port = kb_smb_transport();
if(!port || ! get_port_state(port) )exit(1);

login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

          
soc = open_sock_tcp(port);
if(!soc) exit(1);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 NetUseDel();
 exit(0);
}


for (i=0; path[i]; i++) {
       key_h = RegOpenKey(handle:handle, key:path[i], mode:MAXIMUM_ALLOWED);
       if ( !isnull(key_h) ) 
       { 
         RegCloseKey(handle:key_h);
         RegCloseKey(handle:handle);
	 security_hole(kb_smb_transport()); 
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();

