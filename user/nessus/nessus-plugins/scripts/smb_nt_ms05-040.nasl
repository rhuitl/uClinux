#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19403);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2005-0058");
 script_bugtraq_id (14518);

 name["english"] = "Vulnerability in Telephony Service Could Allow Remote Code Execution (893756)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the 
Telephony service.

Description :

The remote host contains a version of the Telephony service which is
vulnerable to a security flaw which may allow an attacker to execute
arbitrary code and take control of the remote host.

On Windows 2000 and Windows 2003 the server must be enabled and only
authenticated user can try to exploit this flaw.

On Windows 2000 Pro and Windows XP this is a local elevation of
privilege vulnerability.

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms05-040.mspx

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:L/Au:R/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 893756";

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
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Tapisrv.dll", version:"5.2.3790.366", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Tapisrv.dll", version:"5.2.3790.2483", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Tapisrv.dll", version:"5.1.2600.1715", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Tapisrv.dll", version:"5.1.2600.2716", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", sp:4, file:"Tapisrv.dll", version:"5.0.2195.7057", dir:"\system32") )
   security_warning (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"893756") > 0 ) security_warning(get_kb_item("SMB/transport"));
