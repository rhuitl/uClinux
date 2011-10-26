#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
#
# See the Nessus Scripts License for details
#

if(description)
{ 
 script_id(10192);
 script_version ("$Revision: 1.12 $");
 
 name["english"] = "Proxy accepts CONNECT requests";
 name["francais"] = "Le proxy accepte les requètes CONNECT";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "The proxy allows the users to perform
CONNECT requests like 
	CONNECT http://cvs.nessus.org:23 

This request give to the person who make it the ability
to have an interactive session.

This problem may allow attackers to go through your
firewall, by connecting to sensitive ports like 23 (telnet) 
using your proxy, or it can allow internal users to bypass the firewall
rules and connect to ports they should not be allowed to. 

In addition to that, your proxy may be used to perform attacks against
other networks.

Solution: reconfigure your proxy so that it refuses CONNECT requests.

Risk factor : High";

 desc["francais"] = "Le proxy autorise les utilisateurs
faire des requêtes CONNECT, telles que :

	CONNECT http://cvs.nessus.org:23

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

Solution : reconfigurez votre proxy en interdisant explicitement
les requêtes CONNECT.

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
proxy_use = get_kb_item("Proxy/usage");
if(proxy_use)
{
 if(get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if(soc)
  {
  command = string("CONNECT ", get_host_name(),":1234 HTTP/1.0\r\n\r\n");
  send(socket:soc, data:command);
  buffer = recv_line(socket:soc, length:4096);
  if((" 200 " >< buffer)||(" 503 "><buffer))security_hole(port);
  close(soc);
  }
 }
}
