#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10555);
 script_bugtraq_id(1973);
 script_version ("$Revision: 1.18 $");
 
 name["english"] =  "Domain account lockout vulnerability";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A security update is missing on the remote host.

Description :

The hotfix for the 'domain account lockout' problem has
not been applied.

This vulnerability allows a user to bypass the domain 
account lockout policy, and hence attempt to brute force
a user account.

Solution : 

See http://www.microsoft.com/technet/security/bulletin/ms00-089.mspx

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


 desc["francais"] = "
Le patch pour la vulnérabilité de verrouillage de compte
du domaine n'a pas été appliqué.

Cette vulnérabilité permet à un pirate d'outrepasser la
politique de verrouillage des comptes du domaine, et 
par conséquent lui permet de tenter d'obtenir le
mot de passe d'un compte par force brute.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-089.mspx
Facteur de risque : Moyen";


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

if ( hotfix_check_sp(win2k:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q274372") > 0 ) 
	security_warning(get_kb_item("SMB/transport"));

