#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20000);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(15065);
 script_cve_id("CVE-2005-2120");

 name["english"] = "Vulnerability in Plug and Play Could Allow Remote Code Execution and Local Elevation of Privilege (905749)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A flaw in the Plug and Play service may allow an authenticated attacker 
to execute arbitrary code on the remote host and therefore elevate his 
privileges.

Description :

The remote host contain a version of the Plug and Play service which
contains a vulnerability in the way it handles user-supplied data.

An authenticated attacker may exploit this flaw by sending a malformed
RPC request to the remote service and execute code within the SYSTEM
context.


Solution : 

Microsoft has released a set of patches for Windows 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms05-047.mspx

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:L/Au:R/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 905749";

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


if ( hotfix_check_sp(xp:3, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"umpnpmgr.dll", version:"5.1.2600.1734", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"umpnpmgr.dll", version:"5.1.2600.2744", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"umpnpmgr.dll", version:"5.0.2195.7069", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"905749") > 0 ) security_warning(get_kb_item("SMB/transport"));
