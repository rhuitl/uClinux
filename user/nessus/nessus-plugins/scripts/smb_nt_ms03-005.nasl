#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11231);
 script_bugtraq_id(6778);
 script_cve_id("CVE-2003-0004");
 script_version("$Revision: 1.12 $");

 name["english"] = "Unchecked Buffer in XP Redirector (Q810577)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote version of Windows contains a buffer overflow in the Windows
Redirector service which may allow an attacker to execute arbitrary code
on the remote host with the SYSTEM privileges.

Solution : 

Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms03-005.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix Q810577";

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

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Mrxsmb.sys", version:"5.1.2600.1143", dir:"\system32\Drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Mrxsmb.sys", version:"5.1.2600.106", dir:"\system32\Drivers") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"810577") > 0 &&
          hotfix_missing(name:"885835") > 0  )
	security_hole(get_kb_item("SMB/transport"));
