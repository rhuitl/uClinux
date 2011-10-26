#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22538);
 script_version("$Revision: 1.1 $");
 script_bugtraq_id(20318);
 script_cve_id("CVE-2006-4692");

 name["english"] = "Vulnerability in Windows Object Packager Could Allow Remote Execution (924496)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to execute code on the remote host.

Description :

The remote host runs a version of Windows which has a flaw in its Object
Packager.

The flaw may allow an attacker to execute code on the remote host.

To exploit this vulnerability, an attacker needs to entice a user to
visit a malicious web site.

Solution : 

Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-065.mspx

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the remote registry for 9224496";

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


if ( hotfix_check_sp(xp:3, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Shdocvw.dll", version:"6.0.3790.588", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Shdocvw.dll", version:"6.0.3790.2783", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shdocvw.dll", version:"6.0.2800.1892", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Shdocvw.dll", version:"6.0.2900.2987", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( ( hotfix_missing(name:"924496") > 0 ) )
   security_warning(get_kb_item("SMB/transport"));
}
