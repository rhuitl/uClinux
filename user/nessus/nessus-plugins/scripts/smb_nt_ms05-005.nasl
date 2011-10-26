#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16332);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0848");
 script_bugtraq_id(12480);
 name["english"] = "Vulnerability in Microsoft Office XP could allow Remote Code Execution (873352)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the Office client.

Description :

The remote host is running a version of Microsoft Office which contains
a security flaw which may allow an attacker to execute arbitrary
code on the remote host.

To exploit this flaw, an attacker would need to send a specially crafted file
to a user on the remote host and wait for him to open it using Microsoft Office.

When opening the malformed file, Microsoft Office will encounter a buffer
overflow which may be exploited to execute arbitrary code.

Solution : 

Microsoft has released a patch for Office XP :

http://www.microsoft.com/technet/security/bulletin/ms05-005.mspx

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of MSO.dll";

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

office_version = hotfix_check_office_version ();
if ( !office_version || (office_version >!< "10.0"))
  if ( ! hotfix_check_works_installed () )
    exit (0);

rootfile = hotfix_get_commonfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Shared\Office10\mso.dll", string:rootfile);


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
 if ( v[0] == 10 &&  v[1] ==  0 && v[2] < 6735  )
	 security_hole(port);
}

NetUseDel();
