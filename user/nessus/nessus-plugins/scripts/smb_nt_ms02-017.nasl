#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10944);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0007");
 script_bugtraq_id(4426);
 script_version("$Revision: 1.15 $");
 script_cve_id("CVE-2002-0151");
 name["english"] = "MUP overlong request kernel overflow Patch (Q311967)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can elevate his privileges.

Description :

The remote version of Windows contains a flaw in Multiple UNC Provider
(MUP) service which may allow a local user to execute arbitrary code
on the remote host with the SYSTEM privileges.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000 and XP :

http://www.microsoft.com/technet/security/bulletin/ms02-017.mspx

Risk factor : 

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "checks for Multiple UNC Provider Patch (Q311967)";

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

if ( hotfix_check_sp(nt:7, win2k:3, xp:1) <= 0 ) exit(0); 

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:0, file:"Mup.sys", version:"5.1.2600.19", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Mup.sys", version:"5.0.2195.5080", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"4.0", file:"Mup.sys", version:"4.0.1381.7125", dir:"\system32\drivers") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q312895") > 0 &&
          hotfix_missing(name:"Q311967") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));

