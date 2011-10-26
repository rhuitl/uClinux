#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#

if(description)
{
 script_id(11423);
 script_bugtraq_id(7146);
 script_cve_id("CVE-2003-0010");
 script_version("$Revision: 1.16 $");

 name["english"] = "Flaw in Windows Script Engine (Q814078)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through the web client.

Description :

The remote host is vulnerable to a flaw in the Windows Script Engine,
which provides Windows with the ability to execute script code.

To exploit this flaw, an attacker would need to lure one user on this
host to visit a rogue website or to send him an HTML e-mail with a
malicious code in it.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms03-008.mspx

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q814078";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");


if ( hotfix_check_sp(xp:2, win2k:4) <= 0 ) exit(0);

	
rootfile = hotfix_get_systemroot();
if(!rootfile) exit(1);


share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\System32\Jscript.dll", string:rootfile);

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(!get_port_state(port))exit(1);
soc = open_sock_tcp(port);
if(!soc)exit(1);


session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) 
 exit(1);


handle =  CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 if ( isnull(version) )
 {
  NetUseDel();
  exit(1);
 }

 if ( ( version[0] == 5 && version[1] == 1 && version[2] == 0 && version[3] < 8513 ) ||
      ( version[0] == 5 && version[1] == 6 && version[2] == 0 && version[3] < 8513 )   )
	security_warning(port);

 CloseFile(handle:handle);
}

NetUseDel();
