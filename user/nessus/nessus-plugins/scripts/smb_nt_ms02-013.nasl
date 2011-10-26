#
# (C) Tenable Network Security
#
# Ref: http://www.microsoft.com/technet/security/bulletin/ms02-013.mspx
#
# Supercedes : MS99-031, MS99-045, MS00-011, MS00-059, MS00-075, MS00-081
#

if(description)
{
 script_id(11326);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"1999-t-0008");
 script_bugtraq_id(4228, 4392);
 script_cve_id("CVE-2002-0058", "CVE-2002-0078");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-A-0015"); 
 script_version("$Revision: 1.16 $");

 name["english"] = "Cumulative VM update";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the WM.

Description :

The Microsoft VM is a virtual machine for the Win32 operating environment.

There are numerous security flaws in the remote Microsoft VM which
could allow an attacker to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to set up a malicious
web site with a rogue Java applet and lure the user of this host
to visit it. The java applet could then execute arbitrary commands
on this host.

Solution : 

Microsoft has released a set of patches for the Windows WM :

http://www.microsoft.com/technet/security/bulletin/ms02-013.mspx

Risk factor : 

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of JView.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nt_ms03-011.nasl");
 script_require_keys("SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if (  get_kb_item("KB816093") ) exit(0);





rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\System32\Jview.exe", string:rootfile);



port    =  kb_smb_transport();
if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
if ( r != 1 ) exit(1);

handle =  CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
  # Fixed in 5.0.3.3805 or newer
  if ( v[0] < 5 || (v[0] == 5 && v[1] == 0 && ( v[2] < 3 || ( v[2] == 3 && v[3] < 3805 ) ) ) )
	security_hole ( port );
 } 
 else 
 {
  NetUseDel();
  exit(1);
 }
}

NetUseDel();

