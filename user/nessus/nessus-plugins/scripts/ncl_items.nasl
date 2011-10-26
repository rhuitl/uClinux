#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Reference:
# http://members.cox.net/ltlw0lf/printers.html
# 

if(description)
{
 script_id(10146);
 script_bugtraq_id(806);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-1508");
 name["english"] = "Tektronix /ncl_items.html";
 name["francais"] = "Tektronix /ncl_items.html";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The file /ncl_items.html or /ncl_subjects.html exist on the remote system.
It is very likely that this file will allow an attacker
to reconfigure your Tektronix printer.

An attacker can use this to prevent the users of your
network from working properly by preventing them
from printing their files.

Solution : Filter incoming traffic to port 80 to this
device, or disable the Phaserlink webserver on the
printer (can be done by requesting http://printername/ncl_items?SUBJECT=2097)

Risk factor : Low";


 desc["francais"] = "
Le fichier /ncl_items.html existe sur le serveur distant.
Il est plus que probable que ce fichier permette à un pirate
de reconfigurer cette imprimante Tektronix.

Un pirate peut utiliser ceci pour empecher les utilisateurs
de votre réseau de travailler convenablement en les empechant
d'imprimer leurs fichiers.

Solution : filtrez le traffic entrant vers le port 80 en direction
de cette imprimante, ou désactivez le serveur web Phaserlink
de celle-ci en faisant la requète http://printername/ncl_items?SUBJECT=2097)

Facteur de risque : Faible";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /ncl_*.html";
 summary["francais"] = "Vérifie la présence de /ncl_*.html";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

i = "/ncl_items.html?SUBJECT=1";
if (is_cgi_installed_ka(item: i, port: port))
{
    	if (!is_cgi_installed_ka(item: "/nessus" + rand() + ".html", port: port) ) {
	 security_hole(port);
	 exit(0);
	}
}

if (is_cgi_installed_ka(item: "/ncl_subjects.html", port: port) )
{
    if (!is_cgi_installed_ka(item: "/nessus" + rand() + ".html", port: port) ) security_hole(port);
}

