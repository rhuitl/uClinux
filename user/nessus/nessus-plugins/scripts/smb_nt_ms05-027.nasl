#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18483);
 script_version("$Revision: 1.9 $");
 script_bugtraq_id(13942);
 script_cve_id("CVE-2005-1208");

 
 script_version("$Revision: 1.9 $");
 name["english"] = "Vulnerability in SMB Could Allow Remote Code Execution (896422)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the 
SMB implementation.

Description :

The remote version of Windows contains a flaw in the Server Message
Block (SMB) implementation which may allow an attacker to execute arbitrary 
code on the remote host.

An attacker does not need to be authenticated to exploit this flaw.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-027.mspx

Risk factor : 

Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 896422";

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


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if ( hotfix_check_sp(xp:3, win2003:2, win2k:6) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Srv.sys", version:"5.2.3790.324", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Srv.sys", version:"5.2.3790.2437", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Srv.sys", version:"5.1.2600.1683", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Srv.sys", version:"5.1.2600.2673", dir:"\system32\drivers") ||
      hotfix_is_vulnerable (os:"5.0", file:"Srv.sys", version:"5.0.2195.7044", dir:"\system32\drivers") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"896422") > 0 )
	{
	 if ( hotfix_check_sp(xp:3, win2003:2) > 0 && hotfix_missing(name:"917159") <= 0 ) exit(0);
	 security_hole(get_kb_item("SMB/transport"));
	}


