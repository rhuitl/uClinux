#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19404);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0026");
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2005-1218");
 script_bugtraq_id(14259);

 name["english"] = "Vulnerability in Remote Desktop Protocol Could Allow Denial of Service (899591)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote desktop service.

Description :

The remote host contains a version of the Remote Desktop protocol/service
which is vulnerable to a security flaw which may allow an attacker to crash
the remote service and cause the system to stop responding.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-041.mspx

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 899591";

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
if ( hotfix_check_sp(win2k:6) > 0)
{
 if ( hotfix_check_nt_server() <= 0 ) 
   exit(0); 
} 

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Rdpwd.sys", version:"5.2.3790.348", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Rdpwd.sys", version:"5.2.3790.2465", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Rdpwd.sys", version:"5.1.2600.1698", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Rdpwd.sys", version:"5.1.2600.2695", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"Rdpwd.sys", version:"5.0.2195.7055", dir:"\system32\drivers") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"899591") > 0 ) security_warning(get_kb_item("SMB/transport"));
