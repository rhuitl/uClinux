#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22032);
 script_version("$Revision: 1.6 $");
 script_bugtraq_id(18912, 18911, 18905, 18889);
 script_cve_id("CVE-2006-1316", "CVE-2006-1540", "CVE-2006-2389");
 
 name["english"] = "Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (917284)";
 

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Microsoft
Office.

Description :

The remote host is running a version of Microsoft Office
which is subject to various flaws which may allow arbitrary code 
to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to 
a user of the remote computer and have it open it with
Microsoft Office.

Solution : 

Microsoft has released a set of patches for Office 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-038.mspx

Risk factor : 

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of MSO.dll";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
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

office_version = hotfix_check_office_version ();
if ( !office_version ) exit(0);

rootfile = hotfix_get_commonfilesdir();
if ( ! rootfile ) exit(1);


if ( "9.0" >< office_version )
	{
	rootfile = hotfix_get_programfilesdir();
	dll  =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Office\Office\mso9.dll", string:rootfile);
	}
else if ( "10.0" >< office_version )
	dll =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Shared\Office10\mso.dll", string:rootfile);
else if ( "11.0" >< office_version )
	dll =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Shared\Office11\mso.dll", string:rootfile);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
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
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( !isnull(v) ) 
  {
  	 if ( ( v[0] == 9 &&  v[1] == 0 && v[2] == 0 && v[3] < 8944 )  ||
	      ( v[0] == 10 && v[1] == 0 && v[2] < 6804 ) ||
	      ( v[0] == 11 && v[1] == 0 && v[2] < 8028 ) ) security_warning(port);
  }
}

NetUseDel();
