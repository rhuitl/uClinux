#
# (C) Tenable Network Security
#


if(description)
{
 script_id(11528);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2003-0111");
 
 name["english"] = "Flaw in Microsoft VM (816093)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the VM.

Description :

The remote host is running a Microsoft VM machine which has a bug
in its bytecode verifier which may allow a remote attacker to execute
arbitrary code on this host, with the privileges of the user running the VM.

To exploit this vulnerability, an attacker would need to send a malformed
applet to a user on this host, and have him execute it. The malicious
applet would then be able to execute code outside the sandbox of the VM.

Solution : 

Microsoft has released a set of patches for the Windows VM :

http://www.microsoft.com/technet/security/bulletin/ms03-011.mspx

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of the remote VM";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys( "SMB/WindowsVersion", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");

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
  # Fixed in 5.0.3.3810 or newer
  if ( v[0] < 5 || (v[0] == 5 && v[1] == 0 && ( v[2] < 3 || ( v[2] == 3 && v[3] < 3810 ) ) ) )
	security_warning ( port );
  else
	set_kb_item(name:"KB816093", value:TRUE);
 } 
 else 
 {
  NetUseDel();
  exit(1);
 }
}

NetUseDel();
