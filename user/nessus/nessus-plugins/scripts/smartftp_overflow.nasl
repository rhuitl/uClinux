#
# (C) Tenable Network Security
#
# 
# Ref: 
#
# Date: Mon, 09 Jun 2003 12:19:40 +0900
# From: ":: Operash ::" <nesumin@softhome.net>
# To: bugtraq@securityfocus.com
# Subject: [SmartFTP] Two Buffer Overflow Vulnerabilities
#

 desc["english"] = "
Synopsis :

It is possible to execute arbitrary code on the remote host thru a remote 
FTP client.

Description :


The remote host is running SmartFTP - an FTP client.

There is a flaw in the remote version of this software which may allow an 
attacker to execute arbitrary code on this host.

To exploit it, an attacker would need to set up a rogue FTP server and have 
a user on this host connect to it.

Solution : 

Upgrade to version 1.0.976.x or newer

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if(description)
{
 script_id(11709);
 script_bugtraq_id(7858, 7861);
 script_version("$Revision: 1.6 $");

 name["english"] = "SmartFTP Overflow";

 script_name(english:name["english"]);
 


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of SmartFTP";

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
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\SmartFTP\SmartFTP.exe", string:rootfile);

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


handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 version = GetFileVersion (handle:handle);
 CloseFile(handle:handle);
 if ( isnull(version) )
	{
	 NetUseDel();
	 exit(1);
	}

 if ( version[0] < 1 || ( version[0] == 1  && version[1] == 0 && version[2] < 976 ) )
	security_warning( port : port, data : desc["english"] + '\n\nPlugin output :\n\n' + rootfile + ' version '+   version[0] + '.' + version[1] + '.' + version[2] + '.' + version[3] + ' is installed on the remote host' );

}

NetUseDel();
