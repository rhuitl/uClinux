#
# Copyright (C) 2004 Tenable Network Security 
#
#

if(description)
{
 script_id(12014);
 script_version("$Revision: 1.3 $");

 name["english"] = "FREE COMMUNITY detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the FREE COMMUNITY program.  
You should ensure that:
- the user intended to install FREE COMMUNITY (it is sometimes silently 
installed)
- the use of FREE COMMUNITY matches your corporate mandates and security policies.

To remove this sort of software, you may wish to check out ad-aware or spybot. 

See also : http://pestpatrol.com/PestInfo/f/free_community.asp 

Solution : Uninstall this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "FREE COMMUNITY detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/registry_full_access");

 script_require_ports(139, 445);
 exit(0);
}


# start the script
include("smb_func.inc");
if ( ! get_kb_item("SMB/registry_full_access") ) exit(0);


path[0] = "software\classes\clsid\{2e9caff6-30c7-4208-8807-e79d4ec6f806}";
path[1] = "software\microsoft\windows\currentversion\explorer\browser helper objects\{2e9caff6-30c7-4208-8807-e79d4ec6f806}";



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
	 security_hole(kb_smb_transport()); 
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();
