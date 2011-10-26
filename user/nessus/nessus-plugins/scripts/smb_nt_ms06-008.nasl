#
# (C) Tenable Network Security
#

if(description)
{
 script_id(20908);
 script_bugtraq_id(16636);
 script_cve_id("CVE-2006-0013");
 script_version("$Revision: 1.3 $");
 name["english"] = "Vulnerability in Web Client Service Could Allow Remote Code Execution (911927)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote version of Windows contains a flaw in the Web Client service which 
may allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need credentials to log into the 
remote host.

Solution : 

Microsoft has released a set of patches for Windows XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-008.mspx

Risk factor : 

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 911927";

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


if ( hotfix_check_sp(xp:3, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Webclnt.dll", version:"5.2.3790.453", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Webclnt.dll", version:"5.2.3790.2591", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Webclnt.dll", version:"5.1.2600.2821", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Webclnt.dll", version:"5.1.2600.1790", dir:"\system32") )
   security_warning(get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else if ( hotfix_missing(name:"911927") > 0 )
	 security_warning(get_kb_item("SMB/transport"));


