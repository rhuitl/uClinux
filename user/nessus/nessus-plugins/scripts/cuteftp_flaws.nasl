#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11756);
 script_cve_id("CVE-2003-1260", "CVE-2003-1261");
 script_bugtraq_id(6642, 6786);
 
 script_version("$Revision: 1.7 $");

 name["english"] = "CuteFTP multiple flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has the program CuteFTP.exe installed.

CuteFTP is a FTP client which contains two overflow conditions
which may be exploited by an attacker to gain a shell on this
host.

To exploit these vulnerabilities, an attacker would need to set
up a rogue FTP server and lure a user of this host to browse it
using CuteFTP.

Solution : Upgrade to CuteFTP 5.0.2.0 or newer
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of CuteFTP.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();


if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);


session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}


key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\GlobalScape Inc.\CuteFTP", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(1);
}

value = RegQueryValue(handle:key_h, item:"CmdLine");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(value) )
{
 NetUseDel();
 exit(1);
}

rootfile = value[1];
NetUseDel(close:FALSE);


share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:rootfile);


r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}


handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);

 if ( !isnull(version) )
 {
 v = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
 if ( version[0] < 5 || (version[0] == 5 && version[1] == 0 && version[2] <= 1 ) ) security_hole(port);
 }
}


NetUseDel();  
