#
# (C) Tenable Network Security
#

if(description)
{
 script_id(10693);
 script_bugtraq_id(2348);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2001-0016");
 
 name["english"] =  "NTLMSSP Privilege Escalation (Q280119)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A bug in the remote operating system allows a local user to elevate his 
privileges.

Description :

The hotfix for the 'NTLMSSP Privilege Escalation' problem has not been 
applied.  This hotfix corrects a problem in Windows NT which may allow a 
local process to execute code with the privileges of the NTLMSSP service
provider.

This vulnerability allows a malicious user, who has the right to log on this 
host locally, to gain additional privileges.

Solution : 

http://www.microsoft.com/technet/security/bulletin/ms01-008.mspx


Risk factor :

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q280119 is installed";
 summary["francais"] = "Détermine si le hotfix Q280119 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 && hotfix_missing(name:"Q280119") > 0 )
	security_warning(get_kb_item("SMB/transport"));

