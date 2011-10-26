#
# Copyright (C) 2004 Tenable Network Security 
#
#

if(description)
{
 script_id(11995);
 
 script_version("$Revision: 1.6 $");

 name["english"] = "BONZI BUDDY detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the BONZI BUDDY program.  
You should ensure that:
- the user intended to install BONZI BUDDY (it is sometimes silently installed) 
- the use of BONZI BUDDY matches your corporate mandates and security policies.

To remove this sort of software, you may wish to check out ad-aware or spybot. 

See also : http://www.safersite.com/PestInfo/b/bonzibuddy.asp
Solution : Uninstall this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "BONZI BUDDY detection";

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
if ( ! get_kb_item("SMB/registry_full_access") ) exit(0);

path[0] = "clsid\{a28c2a31-3ab0-4118-922f-f6b3184f5495}";
path[1] = "software\bonzi software";
path[2] = "software\microsoft\windows\currentversion\explorer\browser helper objects\{18b79968-1a76-4953-9ebb-b651407f8998}";
path[3] = "software\microsoft\windows\currentversion\shareddlls\c:\program files\bonzibuddy\bbuddymini.exe";
path[4] = "software\microsoft\windows\currentversion\shareddlls\c:\program files\limewire\2.8.6\bonzi.url";
path[5] = "software\microsoft\windows\currentversion\shareddlls\c:\windows\system32\bonzitapfilters.dll";
path[6] = "software\microsoft\windows\currentversion\shareddlls\d:\program files\bonzibuddy\bbuddymini.exe";
path[7] = "software\microsoft\windows\currentversion\shareddlls\d:\program files\limewire\3.6.6\bonzi.url";
path[8] = "software\microsoft\windows\currentversion\shareddlls\d:\windows\system32\bonzitapfilters.dll";
path[9] = "software\microsoft\windows\currentversion\shareddlls\d:\winnt\system32\bonzitapfilters.dll";
path[10] = "software\microsoft\windows\currentversion\uninstall\bonzibuddy";



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
