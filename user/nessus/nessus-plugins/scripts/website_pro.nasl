#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10303);
 script_bugtraq_id(932);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0066");
 
 name["english"] = "WebSite pro reveals the physical file path of web directories";
 name["francais"] = "WebSite pro donne le chemin absolu des fichiers html";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "It was possible to
discover the physical location of a
virtual web directory of this host by 
issuing the command :

	GET /HTTP1.0/
	
This can reveal valuable information to an attacker, allowing
them to focus their attack.

Solution : Use another web server.

Risk factor : Low";

 desc["francais"] = "Il s'est avéré possible
d'obtenir l'emplacement physique du
dossier web virtuel de ce serveur
en entrant la commande :

	GET /HTTP1.0/
	
D'habitude, moins les pirates en savent sur
votre système, mieux il se porte, donc vous
devriez corriger ce problème.

Solution : utilisez un autre serveur web

Facteur de risque : Faible";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to find the location of the remote web root";
 summary["francais"] = "Essaye de trouver le chemin d'accès à la racine web distante";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

port = get_http_port(default:80);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  d = string("GET /HTTP1.0/\r\n\r\n");
  send(socket:soc, data:d);
  r = recv(socket:soc, length:2048);
  if("htdocs\HTTP" >< r)security_warning(port);
  close(soc);
 }
}
