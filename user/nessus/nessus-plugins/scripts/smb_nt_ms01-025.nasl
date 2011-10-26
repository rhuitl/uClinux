#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10668);
 script_bugtraq_id(2709);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2001-0244", "CVE-2001-0245");

 
 name["english"] =  "Malformed request to index server";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host

Description :

The hotfix for the 'Malformed request to index server'
problem has not been applied.

This vulnerability can allow an attacker to execute arbitrary
code on the remote host.

Solution :

http://www.microsoft.com/technet/security/bulletin/ms01-025.mspx

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines whether the hotfixes Q294472 and Q296185 are installed";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7, win2k:3) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q299444") > 0 && 
     hotfix_missing(name:"Q296185") > 0 && 
     hotfix_missing(name:"Q294472") > 0 &&
     hotfix_missing(name:"SP2SRP1") > 0 )
	security_hole(get_kb_item("SMB/transport"));

