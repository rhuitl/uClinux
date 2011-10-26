#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10093);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0660");
 name["english"] = "GateCrasher";
 name["francais"] = "GateCrasher";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "GateCrasher is installed. 

This backdoor allows anyone to
partially take the control of 
the remote system.

An attacker may use it to steal your
password or prevent your from working
properly.

Solution : telnet to this host on port 6969,
then type 'gatecrasher;', without the quotes,
and press Enter. Then type 'uninstall;' and
press Enter, it will be uninstalled.

Risk factor : High";


 desc["francais"] = "GateCrasher est installé.

Cette backdoor permet à n'importe qui
de prendre partiellement le controle
de la machine distante.

Un pirate peut l'utiliser pour voler
vos mots de passes ou vous empecher
de travailler convenablement.

Solution : faites un telnet sur la machine
sur le port 6969, tappez 'gatecrasher;' 
sans les guillemets, puis Entrée. Puis
tappez 'uninstall;' sans les guillemets
et Entrée.

Facteur de risque : Elevé.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of GateCrasher";
 summary["francais"] = "Détermines la presence de GateCrasher";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports(6969);
 exit(0);
}

#
# The script code starts here
#

port = 6969;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  a = recv(socket:soc, length:40);
  if("GateCrasher" >< a)security_hole(port);
  close(soc);
 }
}
