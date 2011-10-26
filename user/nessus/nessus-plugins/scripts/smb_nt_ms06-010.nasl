#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20910);
 script_cve_id("CVE-2006-0004");
 script_bugtraq_id(16634);
 
 script_version("$Revision: 1.2 $");

 name["english"] = "Vulnerability in PowerPoint 2000 Could Allow Information Disclosure (889167)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote version of PowerPoint is vulnerable to an information disclosure
vulnerability.

Description :

The remote host contains a version of PowerPoint which is vulnerable to
an information disclosure vulnerability.

Specifically, an attacker could send a malformed PowerPoint file to a
a victim on the remote host. When the victim opens the file, the attacker
may be able to obtain access to the files in the Temporary Internet Files
Folder of the remote host.

Solution :

Microsoft has released a set of patches for PowerPoint :

http://www.microsoft.com/technet/security/bulletin/ms06-010.mspx

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of PowerPnt.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
ppt =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Microsoft Office\Office\PowerPnt.exe", string:rootfile);



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

handle =  CreateFile (file:ppt, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 ppt_version = v =  GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  set_kb_item(name:"SMB/Office/PowerPoint/Version", value:string(v[0], ".", v[1], ".", v[2], ".", v[3]));
 }
}


NetUseDel();

if ( ! isnull(ppt_version) ) 
{
 if ( ppt_version[0] == 9 && ppt_version[1] == 0 && ppt_version[2] == 0 && ppt_version[3] < 8936) 
	security_note(port);
}
