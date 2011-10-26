#
# Copyright (C) 2004 Tenable Network Security 
#
#

if(description)
{
 script_id(12019);
 script_version("$Revision: 1.5 $");

 name["english"] = "WILDTANGENT detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the WILDTANGENT program.  
You should ensure that:
- the user intended to install WILDTANGENT (it is sometimes silently installed)
- the use of WILDTANGENT matches your corporate mandates and security policies.

To remove this sort of software, you may wish to check out ad-aware or spybot. 

See also : http://pestpatrol.com/PestInfo/w/wildtangent.asp
Solution : Uninstall this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "WILDTANGENT detection";

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

path[0] = "software\wildtangent";
path[1] = "software\microsoft\windows\currentversion\uninstall\wtwebdriver";
path[2] = "software\microsoft\windows\currentversion\uninstall\wtdmmp";
path[3] = "software\microsoft\windows\currentversion\uninstall\wcmdmgr.exe";


name = kb_smb_name();
if(!name)exit(0);

port = kb_smb_transport();
if(!port)exit(0);

if(!get_port_state(port)) exit(0);
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();
          
soc = open_sock_tcp(port);
if(!soc) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(0);
}


for (i=0; path[i]; i++)
{
 key_h = RegOpenKey(handle:hklm, key:path[i], mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
 {
  security_hole (port);
  RegCloseKey(handle:key_h);
  break;
 }
}

RegCloseKey (handle:hklm);
NetUseDel ();
