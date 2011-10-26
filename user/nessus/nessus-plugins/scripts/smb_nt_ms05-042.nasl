#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19405);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2005-1981","CVE-2005-1981");
 script_bugtraq_id (14519, 14520);

 name["english"] = "Vulnerability in Kerberos Could Allow Denial of Service, Information Disclosure and Spoofing (899587)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote service or disclose information.

Description :

The remote host contains a version of the Kerberos protocol which is 
vulnerable to multiple security flaws which may allow an attacker to crash
the remote service (AD), disclose information or spoof session.

An attacker need valid credentials to exploit those flaws.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-042.mspx

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 899587";

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
include("smb_hotfixes_fcheck.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"kerberos.dll", version:"5.2.3790.347", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"kerberos.dll", version:"5.2.3790.2464", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"kerberos.dll", version:"5.1.2600.1701", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"kerberos.dll", version:"5.1.2600.2698", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"kerberos.dll", version:"5.0.2195.7053", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"899587") > 0 ) security_warning(get_kb_item("SMB/transport"));
