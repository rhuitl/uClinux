#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Added some extra checks. Axel Nennker axel@nennker.de 20020301

if(description)
{
 script_id(10409);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-1999-0660");
 name["english"] = "SubSeven";
 name["francais"] = "SubSeven";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This host seems to be running SubSeven on this port

SubSeven is trojan which allows an intruder to take the control of the remote 
computer.

An attacker may use it to steal your passwords, modify your data, and 
preventing you from working properly.

Solution : reinstall your system
Risk factor : High";


 desc["francais"] = "
Cette machine semble faire tourner SubSeven 
sur ce port.


SubSeven est un cheval de troie qui
permet à un intrus de prendre le controle de 
ce poste à distance.

Un pirate peut l'utiliser pour voler vos mots de passe,
modifier vos données, et vous empecher de travailler
correctement.

Solution : réinstallez le système
Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Determines the presence of SubSeven";
 summary["francais"] = "Détermine la présence de SubSeven";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service2.nasl");

 
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/subseven");
if (port) security_hole(port);
