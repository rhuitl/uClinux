#
# Copyright (C) 2005 Tenable Network Security
#
if(description)
{
 script_id(17611);
 script_bugtraq_id(12890);
 script_version("$Revision: 1.2 $");

 name["english"] = "Trillian Multiple HTTP Responses Buffer Overflow Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

An attacker may be able to execute arbitrary code on the remote host.

Description :


The remote host has the Trillian program installed. 
Trillian is a Peer2Peer client that allows users to chat and share files
with other users across the world. 

The remote version of this software is vulnerable to several buffer overflows
when processing malformed responses. 

An attacker could exploit these flaws to execute arbitrary code on the remote
host. To exploit these flaws, an attacker would need to divert several HTTP
requests made by the remote host (through DNS poisoning) to a rogue HTTP
server sending malformed data.

Solution : 

Upgrade to a version newer than 3.1.0.121

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Trillian.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

if ( ! get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Trillian/DisplayName") ) exit(0);

programfiles = hotfix_get_programfilesdir();
if ( ! programfiles ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:programfiles);
exe   = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Trillian\Trillian.exe", string:programfiles);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();


if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);


if ( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 set_kb_item(name:"SMB/Trillian/Version", value:version[0] + "." + version[1] + "." + version[2] + "." + version[3]);
 CloseFile(handle:handle);
 if ( version[0] < 3 ||
     ( version[0] == 3 && version[1] < 1 ) ||
     ( version[0] == 3 && version[1] == 1 && version[2] == 0 && version[3] <= 121 ) )
	security_warning(0);
}

NetUseDel();
