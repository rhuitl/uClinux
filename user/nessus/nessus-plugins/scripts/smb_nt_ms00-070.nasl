#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10525);
 script_bugtraq_id(1743);
 script_version ("$Revision: 1.20 $");
 name["english"] = "LPC and LPC Ports Vulnerabilities patch";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can elevate his privileges.

Description :

The hotfix for the multiple LPC and LPC Ports vulnerabilities 
has not been applied on the remote Windows host.

These vulnerabilities allows an attacker gain privileges on the
remote host, or to crash it remotely.

Solution : 

http://www.microsoft.com/technet/security/bulletin/ms00-070.mspx

Risk factor :

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q266433 is installed";
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


if ( hotfix_check_sp(nt:7, win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 &&
     hotfix_missing(name:"Q266433") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
