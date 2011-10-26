#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21694);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-2006-2379");
 script_bugtraq_id(18374);

 name["english"] = "Vulnerability in TCP/IP Could Allow Remote Code Execution (917953)";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to execute code on the remote host.

Description :

The remote version of Windows contains a version of the TCP/IP 
protocol which is vulnerable to a buffer overflow vulnerability.

An attacker may exploit these flaws to execute code on the remote
host.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-032.mspx

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 917953";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Tcpip.sys", version:"5.2.3790.537", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Tcpip.sys", version:"5.2.3790.2709", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Tcpip.sys", version:"5.1.2600.1831", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Tcpip.sys", version:"5.1.2600.2892", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0",       file:"Tcpip.sys", version:"5.0.2195.7087", dir:"\system32\drivers") )
      security_note(get_kb_item("SMB/transport"));
      hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"917953") > 0 ) security_note(get_kb_item("SMB/transport"));
