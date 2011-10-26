#
# Copyright (C) 2004 Tenable Network Security 
#
#

if(description)
{
 script_id(11998);
 script_version("$Revision: 1.3 $");
 name["english"] = "GATOR detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the GATOR program.  
You should ensure that:
- the user intended to install GATOR (it is sometimes silently installed)
- the use of GATOR matches your corporate mandates and security policies.

To remove this sort of software, you may wish to check out ad-aware or spybot. 

Solution : Uninstall this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "GATOR detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");

 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");

# start the script

path[0] = "software\classes\interface\{06dfeda9-6196-11d5-bfc8-00508b4a487d}";

path[1] = "software\classes\interface\{38493f7f-2922-4c6c-9a9a-8da2c940d0ee}";        

path[2] = "software\classes\kbbar.kbbarband\clsid";  

path[3] = "software\gatortest";

path[4] = "software\microsoft\windows\currentversion\stashedgef";

path[5] = "software\microsoft\windows\currentversion\app management\arpcache\gator";

path[6] = "software\microsoft\windows\currentversion\run\trickler";

path[7] = "software\microsoft\windows\currentversion\uninstall\gator";

path[8] = "software\microsoft\windows\currentversion\uninstall\{456ba350-947f-4406-b091-aa1c6678ebe7}";

path[9] = "software\microsoft\windows\currentversion\uninstall\{6c8dbec0-8052-11d5-a9d5-00500413153c}";


if ( ! get_kb_item("SMB/registry_access") ) exit(0);


port = kb_smb_transport();
if(!port || ! get_port_state(port) )exit(0);

name = kb_smb_name ();
if (!name) exit(0);

login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();
          
soc = open_sock_tcp(port);
if(!soc) exit(0);

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

