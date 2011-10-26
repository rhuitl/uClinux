#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10485);
 script_bugtraq_id(1535);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0737");

 name["english"] =  "Service Control Manager Named Pipe Impersonation patch";
 name["francais"] = "Service Control Manager Named Pipe Impersonation patch";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The hotfix for the 'Service Control Manager Named Pipe Impersonation'
problem has not been applied.

This vulnerability allows a malicious user, who has the
right to log on this host locally, to gain additional privileges.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-053.mspx
Risk factor : Medium";


 desc["francais"] = "
Le hotfix pour le problème de spoof du protocole du
serveur de noms NetBIOS n'a pas été appliqué.

Cette vulnérabilité permet à un utilisateur malicieux ayant
le droit de se logguer sur ce serveur locallement d'obtenir
plus de droits sur celui-ci.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-053.mspx
Facteur de risque : Moyen";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q269523 is installed";
 summary["francais"] = "Détermine si le hotfix Q269523 est installé";
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

if ( hotfix_missing(name:"Q269523") > 0 ) 
	security_warning(get_kb_item("SMB/transport"));

