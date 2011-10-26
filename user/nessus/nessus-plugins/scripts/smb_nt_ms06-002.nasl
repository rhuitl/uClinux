#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20389);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(16194);
 script_cve_id("CVE-2006-0010");
 
 name["english"] = "Vulnerability in Embedded Web Fonts Could Allow Remote Code Execution (908519)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host by sending a malformed file
to a victim.

Description :

The remote version of Microsoft Windows contains a flaw in the Embedded Web
Font engine.
An attacker may execute arbitrary code on the remote host by constructing a
malicious web page and entice a victim to visit this web page or by sending
a malicious font file.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-002.mspx

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 908519";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Fontsub.dll", version:"5.2.3790.426", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Fontsub.dll", version:"5.2.3790.2549", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Fontsub.dll", version:"5.1.2600.1762", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Fontsub.dll", version:"5.1.2600.2777", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"Fontsub.dll", version:"5.0.2195.7071", dir:"\system32") )
      security_warning(get_kb_item("SMB/transport"));
      hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"908519") > 0 ) security_warning(get_kb_item("SMB/transport"));
