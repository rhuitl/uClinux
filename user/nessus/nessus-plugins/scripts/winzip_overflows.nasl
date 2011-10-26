#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17362);
 script_cve_id("CVE-2004-1465");
 script_bugtraq_id(11092);
 script_version("$Revision: 1.3 $");

 name["english"] = "WinZip Multiple Overflows";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a version of WinZip which is older than
version 9.0-SR1.

WinZip is a popular ZIP compression tool. The remote version of this
software contains several buffer overflows which may allow an attacker
to execute arbitrary code on the remote host.

To exploit it, an attacker would need to send a malformed archive
file to a user on the remote host and wait for him to open it
using WinZip.

Solution : Upgrade to WinZip 9.0-SR1.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of WinZip";

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

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\WinZip\WinZip32.exe", string:rootfile);

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

 # Version 9.0.0 SR-1 is version 18.0.6224.0
 set_kb_item(name:"SMB/WinZip/Version", value:version[0] + "." + version[1] + "." + version[2] + "." + version[3]);

 if ( version[0] < 18 || ( version[0] == 18  && version[1] == 0 && version[2] < 6224) )
	security_hole ( port );

}

NetUseDel();
