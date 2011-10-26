#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(12108);
 script_bugtraq_id(9872);

 script_version("$Revision: 1.3 $");

 name["english"] = "Multiple Overflows in WS_FTP client";

 script_name(english:name["english"]);

 desc["english"] = "
The remote host has a version of the WS_FTP client which is vulnerable to 
multiple remote exploits.  
An attacker, exploiting these bugs would be able to access confidential 
data on this system.

To exploit this flaw, an attacker would need to lure a user of this host
to visit a rogue FTP server, by inviting him by email, AIM or any other
mean.

Solution : Upgrade to the newest version of the WS_FTP client 
See also : http://www.ipswitch.com/
Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "IPSWITCH WS_FTP client overflow detection";

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

# start script

include("smb_func.inc");
include("smb_hotfixes.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\WS_FTP\WSFTP32.DLL", string:rootfile);

name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();
if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);

 if ( !isnull(version) )
 {
  v = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
  set_kb_item(name:"ws_ftp_client/version", value:v);

  if ( version[0] < 8 ||
     (version[0] == 8 && version[1] == 0 && version[2] == 0 && version[3] < 4 ) ) security_hole(port);
 }
}


NetUseDel();  
