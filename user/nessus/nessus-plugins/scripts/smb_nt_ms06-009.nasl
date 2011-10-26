#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20909);
 script_bugtraq_id(16643);
 script_cve_id("CVE-2006-0008");
 script_version("$Revision: 1.2 $");
 name["english"] = "Vulnerability in Korean Input Method Could Allow Elevation of Privilege (901190)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user may elevate his privileges.

Description :

The remote version of Windows contains a flaw in the Korean input method which 
may allow a local attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need credentials to log into the 
remote host.

Solution : 

Microsoft has released a set of patches for Windows XP and 2003 and Office 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-009.mspx

Risk factor : 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:L/AC:L/Au:NR/C:C/I:C/A:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 901190";

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


#
# XP SP1, SP2, Windows Server 2003 SP0, SP1
#
if ( hotfix_check_sp(xp:3, win2003:2) <= 0 ) exit(0);
if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Imekr61.ime", version:"6.1.3790.1", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Imekr61.ime", version:"6.2.2551.0", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1",       file:"Imekr61.ime", version:"6.1.2600.3", dir:"\system32")  )
     
   security_warning(get_kb_item("SMB/transport"));
 
  hotfix_check_fversion_end(); 
  exit (0);
 }
