#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11541);
 script_bugtraq_id(7370);
 script_cve_id("CVE-2003-0112");
 script_version ("$Revision: 1.17 $");

 name["english"] = "Buffer overrun in NT kernel message handling";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can elevate his privileges.

Description :

The remote version of Windows has a flaw in the way the kernel passes error
messages to a debugger. An attacker could exploit it to gain elevated privileges
on this host.

To successfully exploit this vulnerability, an attacker would need a local
account on this host.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms03-013.mspx

Risk factor :

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks hotfix Q811493";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
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

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Ntkrnlmp.exe", version:"5.1.2600.1151", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Ntkrnlmp.exe", version:"5.1.2600.108", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Ntkrnlmp.exe", version:"5.0.2195.6159", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Ntkrnlmp.exe", version:"4.0.1381.7203", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"Ntkrnlmp.exe", version:"4.0.1381.33545", min_version:"4.0.1381.33000", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else 
if ( hotfix_missing(name:"811493") > 0 && 
     hotfix_missing(name:"840987") > 0 && 
     hotfix_missing(name:"885835") > 0 )
	{
	if ( hotfix_check_sp(xp:2) > 0  &&
	     hotfix_missing(name:"890859") == 0 ) exit(0);

	security_hole(get_kb_item("SMB/transport"));
	}

