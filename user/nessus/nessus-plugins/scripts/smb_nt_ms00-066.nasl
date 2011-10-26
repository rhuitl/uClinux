#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10509);
 script_bugtraq_id(1304);
 script_version ("$Revision: 1.19 $");

 script_cve_id("CVE-2000-0544");
 name["english"] =  "Malformed RPC Packet patch";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

It is possible to crash the remote host

Description :

The hotfix for the 'Malformed RPC Packet' problem has
not been applied.

This vulnerability allows a malicious user,  to cause
a denial of service against this host.

Solution :

http://www.microsoft.com/technet/security/bulletin/ms00-066.mspx

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfix Q272303 is installed";
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
if ( hotfix_missing(name:"Q272303") > 0 )
	security_warning(get_kb_item("SMB/transport"));

