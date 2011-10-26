#
# (C) Tenable Network Security
#
if(description)
{
 script_id(22193);
 script_bugtraq_id(19375, 19384);
 script_cve_id("CVE-2006-3443", "CVE-2006-3648");

 script_version("$Revision: 1.4 $");
 name["english"] = "Vulnerability in Windows Kernel Could Result in Remote Code Execution (917422)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can elevate his privileges on the remote host.

Description :

The remote host contains a version of the Windows kernel which is vulnerable
to a security flaw which may allow a local user to elevate his privileges
or to crash it (therefore causing a denial of service).

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003:

http://www.microsoft.com/technet/security/bulletin/ms06-051.mspx

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 917422 has been installed";

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

if ( hotfix_check_sp(xp:3, win2k:6, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Kernel32.dll", version:"5.2.3790.556", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Kernel32.dll", version:"5.2.3790.2741", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Kernel32.dll", version:"5.1.2600.1869", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Kernel32.dll", version:"5.1.2600.2945", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Kernel32.dll", version:"5.0.2195.7099", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"917422") > 0  )
{
 security_warning(get_kb_item("SMB/transport"));
}

