#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11928);
 script_bugtraq_id(8828);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2003-0711");
 
 name["english"] = "Buffer Overrun in Windows Help (825119)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the Help service.

Description :

A security vulnerability exists in the Windows Help Service that could allow 
arbitrary code execution on an affected system. An attacker who successfully 
exploited this vulnerability could be able to run code with Local System on
this host.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-044.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix 825119";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 script_dependencies("smb_hotfixes.nasl");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");

if ( hotfix_missing(name:"896358") == 0 ) exit(0);


rootfile = hotfix_get_systemroot();
if  ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
itircl =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\system32\itircl.dll", string:rootfile);


port = kb_smb_transport();
if ( ! get_port_state(port) ) exit(1);

soc = open_sock_tcp(port);
if ( ! soc ) exit(1);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 ) exit(1);

handle =  CreateFile (file:itircl, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);


if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) ) 
 {
  if ( v[0] < 5 ||
       ( v[0] == 5 && v[1] < 2) ||
       ( v[0] == 5 && v[1] == 2 && v[2] < 3790 ) ||
       ( v[0] == 5 && v[1] == 2 && v[2] == 3790 && v[3] < 80 )) security_hole(port);
 }
 else {
 NetUseDel();
 exit(1);
 }
}

NetUseDel();
