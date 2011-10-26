#
# Copyright (C) 2004 Tenable Network Security
#
if(description)
{
 script_id(14270);
 script_cve_id("CVE-2004-1714");
 script_bugtraq_id(10915);
 script_version("$Revision: 1.5 $");
 #script_cve_id("");

 name["english"] = "ISS BlackICE Vulnerable Config Files";
 script_name(english:name["english"]);

 desc["english"] = "
ISS BlackICE is a personal Firewall/IDS for windows Desktops.
Based on the version number, the remote Blackice install is
vulnerable to a local attack due to incorrect file permissions.

*** Nessus based the results of this test on the contents of
*** the local Blackice configuration file.  

Solution : Upgrade to the newest version of BlackICE.
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "ISS BlackICE Vulnerable config file detection";

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

name    = kb_smb_name();       
login   = kb_smb_login(); 
pass    = kb_smb_password();    
domain  = kb_smb_domain();      
port    = kb_smb_transport();

if ( ! get_port_state(port) ) exit(1);
soc = open_sock_tcp(port);
if ( ! soc ) exit(1);
session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(0);
}

key_h = RegOpenKey(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\blackd.exe", handle:hklm, mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

item = RegQueryValue(handle:key_h, item:"Default");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(item) ) {
	NetUseDel();
	exit(1);
	}

NetUseDel(close:FALSE);

myfile = str_replace(find:".exe", replace:".log", string:item[1]);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:myfile);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:myfile);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1)
{
 NetUseDel();
 exit(1);
}

handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING) ;

if ( isnull(handle) )
{
 NetUseDel();
 exit(1);
}

myread = ReadFile(handle:handle, length:2048, offset:0);
CloseFile(handle:handle);

if ( isnull(myread) )
{
 NetUseDel();
 exit(1);
}

NetUseDel();
 
myread = str_replace(find:raw_string(0), replace:"", string:myread);

version = egrep(string:myread, pattern:"BlackICE Product Version");
if ( version )
{
	set_kb_item(name:"SMB/BlackICE/Version", value:version);
    	if (ereg(string:version, pattern:"BlackICE Product Version.*3\.([0-5]\.cdf|6\.c(b[drz]|c[a-h]|df))")) security_hole(port);
}
