#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10194);
 script_version ("$Revision: 1.14 $");
 
 name["english"] = "Proxy accepts POST requests";
 name["francais"] = "Le proxy accepte les requêtes POST";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "The proxy allows the users to perform
POST requests like 
	POST http://cvs.nessus.org:21 

Without any Content-length tag.
This request may give an attacker the ability
to have an interactive session.

This problem may allow attackers to go through your
firewall, by connecting to sensitive ports like 23 (telnet) 
using your proxy, or it can allow internal users to bypass the firewall
rules and connect to ports they should not be allowed to. 

In addition to that, your proxy may be used to perform attacks against
other networks.

Solution: reconfigure your proxy so that only the users of the internal
network can use it, and so that it can not connect to dangerous
ports (1-1024).

Risk factor : High";

 desc["francais"] = "Le proxy autorise les utilisateurs
faire des requêtes POST, telles que :

	POST http://cvs.nessus.org:21
	
Sans tag de Content-length.
Cette requête permet à celui qui la fait d'obtenir une session
interactive.

Ce problème peut permettre à des pirates de passer au travers
de votre firewall, en se connectant à des ports sensibles, tels
que 23 (telnet), ou bien il peut permettre aux utilisateurs
internes d'outrepasser les règles de sortie du firewall et ainsi
de se connecter sur des ports auxquels ils n'auraient normallement
pas accès.

En plus de ceci, votre proxy peut etre utiliser pour mener des
attaques contre d'autres réseaux.

Solution : reconfigurez votre proxy de telle sorte que seuls
les utilisateurs de votres réseau interne puissent s'en servir,
et qu'il refuse de se connecter aux ports 1-1024.

Facteur de risque : Très élevé";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Determines if we can use the remote web proxy against any port"; 
 summary["francais"] = "Determine si nous pouvons utiliser le proxy web distant contre n'importe quel port";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Firewalls"; 
 family["francais"] = "Firewalls";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("find_service.nes", "proxy_use.nasl");
 script_require_keys("Proxy/usage");
 script_require_ports("Services/http_proxy", 8080);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/http_proxy");
if(!port) port = 8080;

usable_proxy = get_kb_item("Proxy/usage");
if(usable_proxy)
{
 if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
  command = string("POST http://", get_host_name(),":21/ HTTP/1.0\r\n\r\n");
  send(socket:soc, data:command);
  buffer = recv_line(socket:soc, length:4096);
  if((" 200 " >< buffer)||(" 503 "><buffer))security_hole(port);
  close(soc);
  }
 }
}
