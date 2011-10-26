#
# (C) Tenable Network Security
#
# Ref:
#  From: "Andreas Constantinides" <megahz@megahz.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Plaintext Password in Settings.ini of CesarFTP
#  Date: Tue, 20 May 2003 10:25:56 +0300


if(description)
{
 script_id(11640);
 script_cve_id("CVE-2003-0329");

 
 script_version("$Revision: 1.6 $");

 name["english"] = "CesarFTP stores passwords in cleartext";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has the program CesarFTP.exe installed.

There is a design issue in the program which makes it store
the username and password of the FTP server in cleartext in
the file 'settings.ini'.

Any user with an account on this host may read this file and
use the password to connect to this FTP server.

Solution : None
Risk : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of CesarFTP's settings.ini";

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

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(0);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\CesarFTP\Settings.ini", string:rootfile);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(0);

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 data = ReadFile(handle:handle, length:16384, offset:0);
 if('Password= "' >< data && 'Login= "' >< data) security_warning(port);
 CloseFile(handle:handle);
}

NetUseDel();

