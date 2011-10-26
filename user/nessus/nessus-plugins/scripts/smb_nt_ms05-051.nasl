#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20004);
 script_version("$Revision: 1.7 $");
 script_bugtraq_id(15059, 15058, 15057, 15056);
 script_cve_id("CVE-2005-2119", "CVE-2005-1978", "CVE-2005-1979", "CVE-2005-1980");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2005-A-0030");

 name["english"] = "Vulnerabilities in MSDTC and COM+ Could Allow Remote Code Execution (902400)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A vulnerability in MSDTC and COM+ could allow remote code execution.

Description :

The remote version of Windows contains a version of MSDTC and COM+ which
are vulnerable to several remote code execution, local privilege escalation
and denial of service vulnerabilities.

An attacker may exploit these flaws to obtain the complete control of the
remote host.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-051.mspx

Risk factor :

Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 902400";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"ole32.dll", version:"5.2.3790.374", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"ole32.dll", version:"5.2.3790.2492", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"ole32.dll", version:"5.1.2600.1720", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"ole32.dll", version:"5.1.2600.2726", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"ole32.dll", version:"5.0.2195.7059", dir:"\system32") )
      security_hole(get_kb_item("SMB/transport"));
      hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"902400") > 0 ) 
{
 if (!((hotfix_check_sp (win2k:6) > 0) && ( hotfix_missing(name:"913580") <= 0 )))
   security_hole(get_kb_item("SMB/transport"));
}