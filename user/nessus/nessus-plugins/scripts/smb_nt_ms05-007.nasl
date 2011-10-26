#
# (C) Tenable Network Security
#
if(description)
{
 script_id(16331);
 script_bugtraq_id(12486);
 script_cve_id("CVE-2005-0051");
 script_version("$Revision: 1.5 $");


 name["english"] = "Vulnerability in Windows Could Allow Information Disclosure (888302)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to disclose information about the remote host.

Description :

The remote version of Windows contains a flaw which may allow an attacker
to cause it to disclose information over the use of a named pipe through
a NULL session.

An attacker may exploit this flaw to gain more knowledge about the
remote host.

Solution : 

Microsoft has released a patch for Windows XP :

http://www.microsoft.com/technet/security/bulletin/MS05-007.mspx

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 888302 has been installed";

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

if ( hotfix_check_sp(xp:3) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.1", sp:1, file:"Srvsvc.dll", version:"5.1.2600.1613", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:2, file:"Srvsvc.dll", version:"5.1.2900.2577", dir:"\system32") )
   security_hole (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"888302") > 0  )
   security_warning(get_kb_item("SMB/transport"));
}
