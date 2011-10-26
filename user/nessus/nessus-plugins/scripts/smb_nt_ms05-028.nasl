#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18484);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0021");
 script_version("$Revision: 1.10 $");
 script_bugtraq_id(13950);
 script_cve_id("CVE-2005-1207");
 
 name["english"] = "Vulnerability in Web Client Service Could Allow Remote Code Execution (896426)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote version of Windows contains a flaw in the Web Client service which may allow
an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need credentials to log into the remote host.

Solution : 

Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-028.mspx

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:L/Au:R/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 896426";

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


if ( hotfix_check_sp(xp:2, win2003:1) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Webclnt.dll", version:"5.2.3790.316", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Webclnt.dll", version:"5.1.2600.1673", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"896426") > 0 &&
          hotfix_missing(name:"911927") > 0 )
	 security_warning(get_kb_item("SMB/transport"));


