#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10010);
 script_bugtraq_id(270);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0776");
 name["english"] = "AliBaba path climbing";
 name["francais"] = "Remontée de chemin avec Alibaba";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The remote HTTP server
allows an attacker to read arbitrary files
on the remote web server, simply by adding
dots in front of its name. 

Example:
	GET /../../winnt/boot.ini

will return your C:\winnt\boot.ini file.

Solution : Upgrade your web server to a 
version that solves this vulnerability, or 
consider changing to another web server, such 
as Apache (http://www.apache.org).

Risk factor : High";

 desc["francais"] = "Le serveur HTTP distant
permet à un pirate de lire des fichiers
arbitraires, en rajoutant simplement des
points au début de son nom.
Exemple :
	GET /../../winnt/boot.ini
	
retournera C:\winnt\boot.ini

Solution : Mettez à jour votre server web ou changez-le.

Facteur de risque : Sérieux";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "GET ../../file";
 summary["francais"] = "GET ../../file";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# FP + other Directory Traversal scripts do the same thing
exit (0);

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(port:port, item:"../../../boot.ini");
if( res )security_hole(port);

