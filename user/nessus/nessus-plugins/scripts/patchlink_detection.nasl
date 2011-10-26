#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#
# Tenable grants a special exception for this plugin to use the library 
# 'smb_func.inc'. This exception does not apply to any modified version of 
# this plugin.
#
#

 desc["english"] = "
Synopsis :

The remote host has a patch management software installed on it.

Description :

This script uses Windows credentials to detect whether the remote host
is running Patchlink and extracts the version number if so. 

Patchlink is a fully Internet-based, automated, cross-platform, security
patch management system. 

See also : 

http://www.patchlink.com/

Risk Factor: 

None";


if(description)
{
 script_id(19944);
 script_version("$Revision: 1.2 $");

 name["english"] = "Patchlink Detection";

 script_name(english:name["english"]);

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Patchlink";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav and Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
if(! get_kb_item("SMB/registry_access")) exit(0);

name	= kb_smb_name(); 	
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

key = "SOFTWARE\PatchLink\Agent Installer";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( isnull(key_h)) debug_print("no key");
if ( ! isnull(key_h) )
{
 item = "Version";
 array = RegQueryValue(handle:key_h, item:item);
 version = array[1];
 debug_print(version );
 RegCloseKey(handle:key_h);
}

if ( ! isnull(version) )
{
  info = string("Patchlink version ", version, " is installed on the remote host.");

  report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		info);

  security_note(port:port, data:report);

  set_kb_item(name:"SMB/Patchlink/version", value:version);
}

NetUseDel();

