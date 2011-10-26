#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21331);
 script_bugtraq_id (17905, 17906);
 script_version("$Revision: 1.3 $");
 script_cve_id("CVE-2006-1184", "CVE-2006-0034");

 name["english"] = "Vulnerability in MSDTC Could Allow Denial of Service (913580)";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote MSDTC service.

Description :

The remote version of Windows contains a version of MSDTC which is 
vulnerable to several denial of service vulnerabilities (DoS and
Invalid Memory Access).

An attacker may exploit these flaws to crash the remote service.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-018.mspx

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 913580";

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


if ( hotfix_check_sp(xp:3, win2003:1, win2k:6) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Msdtctm.dll", version:"2001.12.4720.480", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Msdtctm.dll", version:"2001.12.4414.65", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Msdtctm.dll", version:"2001.12.4414.311", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"Msdtctm.dll", version:"2000.2.3535.0", dir:"\system32") )
      security_warning(get_kb_item("SMB/transport"));
      hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"913580") > 0 ) security_warning(get_kb_item("SMB/transport"));
