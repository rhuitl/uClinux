#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20172);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id (15352,15356);
 script_cve_id("CVE-2005-2123", "CVE-2005-2124", "CVE-2005-0803");
 
 name["english"] = "Vulnerabilities in Graphics Rendering Engine Could Allow Code Execution (896424)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host by sending a malformed file
to a victim.

Description :

The remote host contains a version of Microsoft Windows is missing a critical
security update which fixes several vulnerabilities in the Graphic Rendering
Engine, and in the way Windows handles Metafiles.

An attacker may exploit these flaws to execute arbitrary code on the remote
host. To exploit these flaws, an attacker would need to send a specially 
crafted Windows Metafile (WMF) or Enhanced Metafile (EMF) to a victim on
the remote host. When viewing the malformed file, a buffer overflow condition
occurs which may allow the execution of arbitrary code with the privileges of
the user.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP SP2 and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-053.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 896424";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"gdi32.dll", version:"5.2.3790.419", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"gdi32.dll", version:"5.2.3790.2542", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"gdi32.dll", version:"5.1.2600.1755", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"gdi32.dll", version:"5.1.2600.2770", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0",       file:"gdi32.dll", version:"5.0.2195.7069", dir:"\system32") )
      security_hole(get_kb_item("SMB/transport"));
      hotfix_check_fversion_end(); 
}
else if ( hotfix_missing(name:"896424") > 0 ) security_hole(get_kb_item("SMB/transport"));
