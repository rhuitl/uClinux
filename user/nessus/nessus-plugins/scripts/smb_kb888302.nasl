#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16337);
 script_bugtraq_id(12486);
 script_cve_id("CVE-2005-0051");
 script_version("$Revision: 1.5 $");


 name["english"] = "Vulnerability in Windows Could Allow Information Disclosure (888302) (network check)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

System information about the remote host can be obtained by an anonymous
user.

Description :

The remote version of Windows contains a flaw which may allow an attacker
to cause it to disclose information over the use of a named pipe through
a NULL session.

An attacker may exploit this flaw to gain more knowledge about the
remote host.

Solution : 

Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms05-007.mspx

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 888302 has been installed";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nativelanman.nasl");
 script_require_ports(139,445);
 exit(0);
}

include ("smb_func.inc");


os = get_kb_item ("Host/OS/smb") ;

# 'Officially', only XP is affected. 
if ( ! os || "Windows 5.1" >!< os ) exit(0);


name = kb_smb_name();
if(!name)exit(0);

port = int(get_kb_item("SMB/transport"));
if (!port) port = 445;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init (socket:soc, hostname:name);
NetUseAdd (share:"IPC$");

if ( NetSessionEnum(level:SESSION_INFO_10) )
  security_warning(port);

NetUseDel ();

