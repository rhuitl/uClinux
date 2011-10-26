#
# (C) Tenable Network Security
#

if(description)
{
 script_id(17656);
 script_cve_id("CVE-2002-1442", "CVE-2002-1444", "CVE-2004-2475");
 script_bugtraq_id(5424, 5477, 11210);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"10037");
 }
 script_version("$Revision: 1.3 $");

 name["english"] = "Google Toolbar HTML Injection Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Google Toolbar, a toolbar of Internet
Explorer.

The remote version of this software is vulnerable to an HTML injection
vulnerability which may allow an attacker to execute a cross site scripting
attack. 

Solution : Upgrade to a version newer than 2.0.114.1.
See also : http://toolbar.google.com
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of the Google Toolbar";

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
exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Google\GoogleToolbar1.dll", string:rootfile);

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

 set_kb_item(name:"SMB/Google/Toolbar/Version", value:version[0] + "." + version[1] + "." + version[2] + "." + version[3]);

 if ( version[0] < 2 || ( version[0] == 2  && version[1] == 0 && version[2] < 114) || (version[0] == 2 && version[1] == 0 && version[2] == 114 && version[3] <= 1 ) )
	security_hole ( port );

}

NetUseDel();
