#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10563);
 script_bugtraq_id(2022);
 script_cve_id("CVE-2000-1039");
 script_version ("$Revision: 1.20 $");

 
 name["english"] =  "Incomplete TCP/IP packet vulnerability";
 name["francais"] = "Incomplete TCP/IP packet vulnerability";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'incomplete TCP/IP packet'
problem has not been applied.

This vulnerability allows a user to prevent this host
from communicating with the network

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-091.mspx
Risk factor : High";


 desc["francais"] = "
Le patch pour la vulnérabilité de paquets TCP/IP incomplets n'a pas
été installé.

Cette vulnérabilité permet à un pirate d'empecher cette machine
de communiquer avec le réseau.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-091.mspx
Facteur de risque : Sérieux";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q274372 is installed";
 summary["francais"] = "Détermine si le hotfix Q274372 est installé";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 && hotfix_missing(name:"Q275567") > 0 ) 
	security_hole(get_kb_item("SMB/transport"));
	
