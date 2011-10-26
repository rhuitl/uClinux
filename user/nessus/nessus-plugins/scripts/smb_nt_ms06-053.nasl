#
# (C) Tenable Network Security
#
if(description)
{
 script_id(22333);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(19927);
 script_cve_id("CVE-2006-0032");
 name["english"] = "Vulnerability in Indexing Service Could Allow Cross-Site Scripting (920685)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server is vulnerable to a cross-site scripting attack. 

Description :

The remote host is running a version of the Indexing service that
fails to adequately sanitize some requests. Combined with a web server
using this service, this flaw could be exploited by an attacker who would
be able to cause arbitrary HTML and script code to be executed in a user's 
browser within the security context of the affected site. 

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-053.mspx

Risk factor :

Low / CVSS Base Score : 1.8
(AV:R/AC:H/Au:NR/C:N/I:P/A:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if hotfix 920685 has been installed";

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

if ( hotfix_check_sp(xp:3, win2k:6, win2003:2) <= 0 ) exit(0);

if (is_accessible_share())
{
 if ( hotfix_is_vulnerable (os:"5.2", sp:0, file:"Query.dll", version:"5.2.3790.552", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.2", sp:1, file:"Query.dll", version:"5.2.3790.2734", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:1, file:"Query.dll", version:"5.1.2600.1860", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.1", sp:2, file:"Query.dll", version:"5.1.2600.2935", dir:"\system32") ||
      hotfix_is_vulnerable (os:"5.0", file:"Query.dll", version:"5.0.2195.7100", dir:"\system32") )
   security_note (get_kb_item("SMB/transport"));
 
 hotfix_check_fversion_end(); 
 exit (0);
}
else
{
 if ( hotfix_missing(name:"920685") > 0 )
   security_note (get_kb_item("SMB/transport"));
}
