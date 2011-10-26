#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11194);
 script_bugtraq_id(6427);
 script_cve_id("CVE-2002-1327");
 script_version("$Revision: 1.10 $");

 name["english"] = "Unchecked Buffer in XP Shell Could Enable System Compromise (329390)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through Windows Shell.

Description :

The remote version of Windows contains a flaw in the handling of 
audio files (MP3, WMA) in the Windows Shell component which may allow an 
attacker to execute arbitrary code on the remote host with the SYSTEM
privileges.

Solution : 

Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms02-072.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for MS Hotfix 329390, Flaw in Microsoft XP Shell";

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
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Shmedia.dll", version:"6.0.2800.1125", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"Shmedia.dll", version:"6.0.2800.101", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else if ( hotfix_missing(name:"Q329390") > 0 )
	security_hole(get_kb_item("SMB/transport"));
