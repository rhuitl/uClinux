#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10519);
 script_bugtraq_id(1683);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0834");

 name["english"] =  "Telnet Client NTLM Authentication Vulnerability";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It may be possible to steal user credentials.

Description :

The hotfix for the 'Telnet Client NTLM Authentication' problem
has not been applied.

This vulnerability may, under certain circumstances, allow a 
malicious user to obtain cryptographically protected logon 
credentials from another user.

Solution : 

http://www.microsoft.com/technet/security/bulletin/ms00-067.mspx

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q272743 is installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q272743") > 0 ) 
	security_warning(get_kb_item("SMB/transport"));
