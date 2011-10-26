#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22189);
 script_bugtraq_id(19414);
 script_cve_id("CVE-2006-3649");
 
 
 script_version("$Revision: 1.4 $");

 name["english"] = "Vulnerability in Microsoft Visual Basic for Applications Could Allow Remote Code Execution (921645)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through VBA.

Description :

The remote host is running a version of Microsoft Visual Basic for Applications
which is vulnerable to a buffer overflow when handling malformed documents.

An attacker may exploit this flaw to execute arbitrary code on this host, by
sending a malformed file to a user of the remote host.

Solution : 

Microsoft has released a set of patches for Office :

http://www.microsoft.com/technet/security/bulletin/ms06-047.mspx

Risk factor :

Medium / CVSS Base Score : 5.5
(AV:R/AC:H/Au:NR/C:P/I:P/A:P/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of vbe6.dll";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


common = hotfix_get_commonfilesdir();
if ( ! common ) exit(1);



#VBA 6- C:\Program Files\Common Files\Microsoft Shared\VBA\VBA6\vbe6.dll = 6.4.99.72
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:common);
vba6 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Shared\VBA\VBA6\vbe6.dll", string:common);

port = kb_smb_transport();
if ( ! port ) exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 ) exit(1);

handle = CreateFile (file:vba6, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
 if ( v[0] == 6 && ( v[1] < 4 || ( v[1] == 4 && v[2] < 99 ) || ( v[1] == 4 && v[2] == 99 && v[3] < 72 ) ) )
	{
	security_warning(kb_smb_transport());
	NetUseDel();
	exit(0);
	}
 }
 else 
 {
  NetUseDel();
  exit(1);
 }
}


NetUseDel();
