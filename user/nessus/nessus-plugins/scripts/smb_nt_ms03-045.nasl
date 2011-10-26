#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11885);
 script_bugtraq_id(8827);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2003-0659");
 
 name["english"] = "Buffer Overrun in the ListBox and in the ComboBox (824141)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can elevate his privileges.

Description :

A vulnerability exists because the ListBox control and the ComboBox control 
both call a function, which is located in the User32.dll file, that contains 
a buffer overrun. An attacker who had the ability to log on to a system 
interactively could run a program that could send a specially-crafted Windows 
message to any applications that have implemented the ListBox control or the 
ComboBox control, causing the application to take any action an attacker 
specified. An attacker must have valid logon credentials to exploit the 
vulnerability. This vulnerability could not be exploited remotely. 

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms03-045.mspx

Risk factor :

Medium / CVSS Base Score : 4 
(AV:L/AC:L/Au:R/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for hotfix Q824141";

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

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"User32.dll", version:"5.2.3790.73", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"User32.dll", version:"5.1.2600.1255", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:0, file:"User32.dll", version:"5.1.2600.118", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"User32.dll", version:"5.0.2195.6799", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"User32.dll", version:"4.0.1381.7229", dir:"\system32") ||
      hotfix_is_vulnerable (os:"4.0", file:"User32.dll", version:"4.0.1381.33550", min_version:"4.0.1381.33000", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end();
 exit (0);
}
else
{
 if ( hotfix_check_sp(xp:2, nt:7) > 0 )
 {
  if ( hotfix_missing(name:"840987") == 0 ) exit(0);
  if ( hotfix_missing(name:"896424") == 0 ) exit(0);
 }

 if ( hotfix_check_sp(win2k:5) > 0 )
 {
  if ( hotfix_missing(name:"840987") == 0 ) exit(0);
  if ( hotfix_missing(name:"841533") == 0 ) exit(0);
  if ( hotfix_missing(name:"890859") == 0 ) exit(0);
 }

 if (hotfix_missing(name:"891711") == 0) exit (0);

 if ( hotfix_missing(name:"824141") > 0 )
 	security_warning(get_kb_item("SMB/transport"));
}
