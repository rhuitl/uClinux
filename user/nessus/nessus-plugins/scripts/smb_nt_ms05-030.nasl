#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18489);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0018");
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(13951);
 script_cve_id("CVE-2005-1213");
 name["english"] = "Vulnerability in Outlook Express Could Allow Remote Code Execution (897715)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the email client.

Description :

The remote host is running a version of Microsoft Outlook Express which contains
a security flaw which may allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to lure a user to connect to a rogue NNTP
(news) server sending malformed replies to several queries.

Solution : 

Microsoft has released a set of patches for Outlook Express :

Solution : http://www.microsoft.com/technet/security/bulletin/ms05-030.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of MSOE.dll";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Outlook Express\msoe.dll", string:rootfile);




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


handle =  CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 flag = 0;
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 set_kb_item(name:"SMB/OutlookExpress/MSOE.dll/Version", value:string(v[0], ".", v[1], ".", v[2], ".", v[3]));

 if ( hotfix_check_sp(xp:2, win2k:5, win2003:1) <= 0 ) {
	NetUseDel();
	exit(0);
	}

 if ( v[0] == 5 )
	{
	 if ( (v[0] == 5 && v[1] < 50) || 
	      (v[0] == 5 && v[1] == 50 && v[2] < 4952) ||
	      (v[0] == 5 && v[1] == 50 && v[2] == 4952 && v[3] < 2800 ) ) { security_hole(port); flag ++; }
	}
 else if ( v[0] == 6 )
	{
	 if ( ( v[0] == 6 && v[1] == 0 && v[2] < 2800) ||
	      ( v[0] == 6 && v[1] == 0 && v[2] == 2800 && v[3] < 1506 ) ) { security_hole(port); flag ++; }

	  if( ( v[0] == 6 && v[1] == 0 && v[2] > 2800 && v[2] < 3790 ) ||
	      ( v[0] == 6 && v[1] == 0 && v[2] == 3790 && v[3] < 326 ) ) { security_hole(port); flag ++; }
	}

 if ( flag == 0 ) set_kb_item(name:"SMB/897715", value:TRUE);
}

NetUseDel();
