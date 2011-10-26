#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21689);
 script_version("$Revision: 1.4 $");
 script_cve_id("CVE-2006-2370", "CVE-2006-2371");
 script_bugtraq_id(18325, 18358, 18424);

 name["english"] = "Vulnerability in Routing and Remote Access Could Allow Remote Code Execution (911280)";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to execute code on the remote host.

Description :

The remote version of Windows contains a version of RRAS (Routing
and Remote Access Service) which is vulnerable to several memory
corruption vulnerabilities.

An attacker may exploit these flaws to execute code on the remote
service.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-025.mspx

Risk factor :

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 911280";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Rasmans.dll", version:"5.2.3790.529", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Rasmans.dll", version:"5.2.3790.2697", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Rasmans.dll", version:"5.1.2600.1842", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Rasmans.dll", version:"5.1.2600.2908", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"Rasmans.dll", version:"5.0.2195.7093", dir:"\system32") )
      security_warning(get_kb_item("SMB/transport"));
      hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"911280") > 0 ) security_warning(get_kb_item("SMB/transport"));
