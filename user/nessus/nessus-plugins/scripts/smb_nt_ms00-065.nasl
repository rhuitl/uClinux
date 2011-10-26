#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10504);
 script_bugtraq_id(1651);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2000-0851");

 name["english"] =  "Still Image Service Privilege Escalation patch";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A local user can elevate his privileges.

Description :

The hotfix for the 'Still Image Service Privilege Escalation'
problem has not been applied.

This vulnerability allows a malicious user, who has the
right to log on this host locally, to gain additional privileges
on this host.

Solution :

http://www.microsoft.com/technet/security/bulletin/ms00-065.mspx

Risk factor :

High / CVSS Base Score : 7 
(AV:L/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 desc["francais"] = "
Le hotfix pour le problème de l'élévation de privilèges
par le service image n'a pas été installé.

Cette vulnérabilité permet à un utilisateur malicieux ayant
le droit de se logguer sur ce serveur locallement d'obtenir
plus de droits sur celui-ci.

Solution : cf http://www.microsoft.com/technet/security/bulletin/ms00-065.mspx
Facteur de risque : Moyen";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines whether the hotfix Q272736 is installed";
 summary["francais"] = "Détermine si le hotfix Q272736 est installé";
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

if ( hotfix_check_sp(win2k:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q272736") > 0 )
	security_hole(get_kb_item("SMB/transport"));
