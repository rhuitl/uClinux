#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22030);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(18923);
 script_cve_id("CVE-2006-2372");

 
 name["english"] = "Vulnerability in DHCP Client Service Could Allow Remote Code Execution (914388)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the 
DHCP client.

Description :

The remote host contains a DHCP client which is vulnerable to a buffer overrun
vulnerability when receiving a malformed response to a DHCP request.

An attacker may exploit this flaw to execute arbitrary code on the remote
host with 'SYSTEM' privileges.

Typically, the attacker would need to be on the same physical subnet as
this victim to exploit this flaw. Also, the victim needs to be configured
to use DHCP.


Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-036.mspx

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 914388";

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


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Dhcpcsvc.dll", version:"5.2.3790.536", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Dhcpcsvc.dll", version:"5.2.3790.2706", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Dhcpcsvc.dll", version:"5.1.2600.1847", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Dhcpcsvc.dll", version:"5.1.2600.2912", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Dhcpcsvc.dll", version:"5.0.2195.7085", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"914388") > 0 )
	 security_warning(get_kb_item("SMB/transport"));


