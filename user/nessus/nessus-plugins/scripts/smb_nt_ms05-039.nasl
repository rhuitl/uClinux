#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19402);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2005-1983");
 script_bugtraq_id (14513);
 if ( defined_func("script_xref") ) {
	script_xref(name:"IAVA", value:"2005-A-0025");
	script_xref(name:"IAVA", value:"2005-B-0017");
	}
 
 name["english"] = "Vulnerability in Plug and Play Could Allow Remote Code Execution and Elevation of Privilege (899588)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the 
Plug-And-Play service.

Description :

The remote version of Windows contains a flaw in the function 
PNP_QueryResConfList() in the Plug and Play service which may allow an 
attacker to execute arbitrary code on the remote host with the SYSTEM
privileges.

A series of worms (Zotob) are known to exploit this vulnerability in the 
wild.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-039.mspx

Risk factor : 

Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 899588";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"umpnpmgr.dll", version:"5.2.3790.360", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"umpnpmgr.dll", version:"5.2.3790.2477", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"umpnpmgr.dll", version:"5.1.2600.1711", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"umpnpmgr.dll", version:"5.1.2600.2710", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"umpnpmgr.dll", version:"5.0.2195.7057", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"899588") > 0 &&
          hotfix_missing(name:"905749") > 0  ) security_hole(get_kb_item("SMB/transport"));
