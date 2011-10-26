#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11426);
 script_bugtraq_id(3135, 4121, 4122, 5317, 6435, 6747);
 script_cve_id("CVE-2002-0314", "CVE-2002-0315");  
 
 script_version("$Revision: 1.5 $");

 name["english"] = "Kazaa is installed";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Kazaa - a p2p software, which may not 
be suitable for a business environment. 

Solution : Uninstall this software
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if Kazaa is installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "Peer-To-Peer File Sharing";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);


name	= kb_smb_name();
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(1);
soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(1);
}

vuln = 0;



key = "SOFTWARE\Kazaa\CloudLoad";
item = "ExecDir";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);

 if (!isnull (value))
 {
   vuln = 1;
   security_note(port);
 }

 RegCloseKey (handle:key_h);
}

NetUseDel();
