#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11191);
 script_bugtraq_id(5927);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2002-1230");
 name["english"] = "WM_TIMER Message Handler Privilege Elevation (Q328310)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Local users can elevate their privileges on the remote host.

Description :

The remote version of Windows contains a flaw in the handling of 
WM_TIMER messages for interactive processes which may allow a 
local user to execute arbitrary code on the remote host with the
SYSTEM privileges.

Solution : 

Microsoft has released a set of patches for Windows NT, XP and 2000 :

http://www.microsoft.com/technet/security/bulletin/ms02-071.mspx

Risk factor :

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks Registry for WM_TIMER Privilege Elevation Hotfix (Q328310)";

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

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"User32.dll", version:"5.1.2600.1134", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"User32.dll", version:"5.1.2600.104", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"User32.dll", version:"5.0.2195.6097", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"User32.dll", version:"4.0.1381.7202", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"User32.dll", version:"4.0.1381.33544", min_version:"4.0.1381.33000", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else
{
 if ( hotfix_check_sp(nt:7) > 0 )
 {
  if (hotfix_missing(name:"840987") == 0 ) exit(0);
 }
 if ( hotfix_check_sp(win2k:4) > 0 )
 {
  if (hotfix_missing(name:"840987") == 0 ) exit(0);
  if (hotfix_missing(name:"841533") == 0 ) exit(0);
 }

 if ( hotfix_missing(name:"328310") > 0 ) 
   security_hole(get_kb_item("SMB/transport"));
}
