#
# Copyright (C) 2004 Tenable Network Security 
#
exit(0); # Too many "false positives"

if(description)
{
 script_id(12009);
 script_version("$Revision: 1.5 $");

 name["english"] = "ALEXA detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the ALEXA program. This software is bundled by
default with Internet Explorer 6.

This software transmits the complete url of the search results to both
'msn.com' and 'alexa.com', thus potentially violating the privacy of the
remote user.

You should ensure that:
- the user intended to install ALEXA
- the use of ALEXA matches your corporate mandates and security policies.

To remove this sort of software, you may wish to check out ad-aware or spybot. 

See also : http://pestpatrol.com/PestInfo/a/alexa.asp
Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "ALEXA detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl");
 script_require_keys("SMB/registry_full_access");

 script_require_ports(139, 445);
 exit(0);
}

# start the script
include("smb_func.inc");
if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(0);


path[0] = "software\classes\clsid\{3df73df8-41e2-4fc2-8cbf-4b9407433755}";
path[1] = "software\microsoft\internet explorer\extensions\{c95fe080-8f5d-11d2-a20b-00aa003c157a}";


port = kb_smb_transport();
if(!port || ! get_port_state(port) )exit(0);

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
	 security_note(port); 
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();
