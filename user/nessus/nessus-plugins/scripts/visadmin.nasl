#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10295);
 script_bugtraq_id(1808);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-1999-0970");
 
 name["english"] = "OmniHTTPd visadmin exploit";
 name["francais"] = "Exploitation du cgi visadmin de OmniHTTPd";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "It is possible to fill the hard disk of a server
running OmniHTTPd by issuing the request :
	http://omni.server/cgi-bin/visadmin.exe?user=guest
This allows an attacker to crash your web server.
This script checks for the presence of the faulty CGI, but
does not execute it.

Solution : remove visadmin.exe from /cgi-bin.

Risk factor : Medium / High";

 desc["francais"] = "Il est possible de remplir le disque dur 
d'un serveur OmniHTTPd en faisant la requete suivante :
 	http://omni.server/cgi-bin/visadmin.exe?user=guest
Ce problème permet à un attaquant de tuer votre serveur.
Ce script vérifie la présence du CGI coupable, mais ne l'exécute
pas.

Solution : retirez visadmin.exe du dossier cgi-bin.

Facteur de risque : Moyen/Elevé";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "Checks for the visadmin.exe cgi";
 summary["francais"] = "Vérifie la présence de visadmin.exe";
 
 script_summary(english:summary["english"],
 	 	francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# Script code
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( ! banner || "OmniHTTP" >!< banner ) exit(0);

res = is_cgi_installed_ka(port:port, item:"visadmin.exe");
if(res)security_warning(port);
