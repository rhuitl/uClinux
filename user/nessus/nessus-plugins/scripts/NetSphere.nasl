#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 name["english"] = "NetSphere Backdoor";
 name["francais"] = "NetSphere";
 name["deutsch"] = "NetShpere";

 script_name(english:name["english"], francais:name["francais"], deutsch:name["deutsch"]);
 script_id(10005);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0660");
 desc["english"] = "NetSphere is installed. 

This backdoor allows anyone to partially take 
control of the remote system.

An attacker may use this vulnerability to 
steal confidential data, prevent your system 
from working properly, or launch attacks against
other machines on your network.

Solution: Telnet to this computer on TCP 
port 30100 and type : '<KillServer>', without 
the quotes, and press Enter. This will stop 
the NetSphere service.  You should then manually
determine a root cause as to how the machine
came to be configured with a backdoor and clean
accordingly.

Risk factor : High";


 desc["francais"] = "NetSphere est installé.

Cette backdoor permet à n'importe qui
de prendre partiellement le controle
de la machine distante.

Un pirate peut l'utiliser pour voler
vos mots de passe ou vous empecher
de travailler convenablement.

Solution : connectez vous à la machine
distante au port 30100 et tappez :
'<KillServer>', sans les guillemets,
et Entrée. Ce backdoor ne sera
plus installé sur votre machine.

Facteur de risque : Elevé.";

 desc["deutsch"] = "NetSphere ist installiert.

Diese Hintertuer erlaubt jedermann die
Kontrolle ueber das System an sich zu
nehmen.

Ein Cracker kann es benutzen, um Ihre Passwoerter
auszuspionieren, oder um Sie vom produktiven
Arbeiten an Ihrer Maschine zu hindern.

Loesung: Oeffnen sie eine Telnet-Sitzung zum
Zielcomputer auf Port 30100 and schreiben Sie :
<KillServer>
Ein Druck auf Enter, und der NetSphere-Server
wird deinstalliert.

Risiko Faktor:	Hoch";

 script_description(english:desc["english"], francais:desc["francais"], deutsch:desc["deutsch"]);
 
 summary["english"] = "Checks for the presence of NetSphere";
 summary["francais"] = "Determines la presence de NetSphere";
 summary["deutsch"] = "Ueberprueft die Existenz von NetSphere";

 script_summary(english:summary["english"], francais:summary["francais"], deutsch:summary["deutsch"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison",
		deutsch:"Dieses Script ist Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 family["deutsch"] = "Hintertueren";

 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
 script_dependencie("find_service.nes");
 script_require_ports(30100);
 exit(0);
}

#
# The script code starts here
#

port = 30100;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  a = recv_line(socket:soc, length:40);
  if("NetSphere" >< a)security_hole(port);
  close(soc);
 }
}
