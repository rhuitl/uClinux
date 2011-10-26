# (C) Tenable Network Security
#
# 
# Ref: 
#
# Date: Mon, 09 Jun 2003 12:19:39 +0900
# From: ":: Operash ::" <nesumin@softhome.net>
# To: bugtraq@securityfocus.com
# Subject: [FlashFXP] Two Buffer Overflow Vulnerabilities
#

if(description)
{
 script_id(11710);
 script_bugtraq_id(7857, 7859);
 script_version("$Revision: 1.6 $");

 name["english"] = "FlashFXP Overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running FlashFXP - an FTP client.

There is a flaw in the remote version of this software which may 
allow an attacker to execute arbitrary code on this host.

To exploit it, an attacker would need to set up a rogue FTP
server and have a user on this host connect to it.

Solution : Upgrade to version 2.1 or newer
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of FlashFXP";

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
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\FlashFXP\FlashFXP.exe", string:rootfile);



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

fid = CreateFile(file:exe);
if ( isnull( fid ))
{
 NetUseDel();
 exit(0);
}


version = GetFileVersion (handle:fid);
CloseFile(handle:fid);
NetUseDel();

if( isnull(version) )exit(1);
if ( version[0] < 2 || (version[0] == 2 && version[1] == 0 ) ) security_hole(port);
