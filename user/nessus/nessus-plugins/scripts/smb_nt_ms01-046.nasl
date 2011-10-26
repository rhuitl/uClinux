#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10734);
 script_bugtraq_id(3215);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2001-0659");
 
 name["english"] =  "IrDA access violation patch";
 
 script_name(english:name["english"]);
 	     
 
 desc["english"] = "
Synopsis :

It is possible to remotely shutdown the server

Description :

The hotfix for the 'IrDA access violation patch' problem 
has not been applied.

This vulnerability can allow an attacker who is physically
near the W2K host to shut it down using a remote control.

Solution :

http://www.microsoft.com/technet/security/bulletin/ms01-046.mspx

See also :

POST SP2 Security Rollup:
http://www.microsoft.com/windows2000/downloads/critical/q311401/default.asp

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:N/A:C/I:N/B:A)";




 script_description(english:desc["english"]);
 		    
 
 summary["english"] = "Determines whether the hotfix  Q252795 is installed";
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

if ( hotfix_check_sp(win2k:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"SP2SRP1") > 0 &&
     hotfix_missing(name:"Q252795") > 0 )
	security_warning(get_kb_item("SMB/transport"));

