#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Should also cover BID: 3035, BID: 3050
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10187);
 script_bugtraq_id(491);
 script_version ("$Revision: 1.19 $");

 name["english"] = "Cognos Powerplay WE Vulnerability";
 name["francais"] = "Cognos Powerplay WE Vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
 The CGI script ppdscgi.exe, part of the PowerPlay 
Web Edition package, is installed.

Due to design problems as well as some 
potential web server misconfiguration 
PowerPlay Web Edition may serve up data 
cubes in a non-secure manner. Execution 
of the PowerPlay CGI pulls cube data into 
files in an unprotected temporary directory. 
Those files are then fed back to frames in 
the browser. In some cases it is trivial for an
unauthenticated user to tap into those data 
files before they are purged.

Solution : Cognos doesn't consider this
problem as being an issue, so they
do not provide any solution.

Risk factor : Medium";

 
 desc["francais"] = "
Le cgi ppdscgi.exe, appartenant au
package PowerPlay Web Edition, est
installé.

A cause de certains problèmes de 
conception ainsi que d'une eventuelle
mauvaise configuration du serveur
web, PowerPlay Web Edition peut
servir des 'data cubes' de 
maniere non sécurisée.

L'execution du CGI PowerPlay met
les CGIs dans un dossier temporaire
non protégé. Ces fichiers sont 
ensuite renvoyés dans les frames du
browser. Dans certains cas, il
peut être trivial pour un utilisateur
non authentifié de lire ces fichiers
avant qu'ils ne soient effacés.

Solution : Cognos ne considere pas ceci
comme étant un problème et n'offre pas
de solution. 

Facteur de risque : Moyen";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the ppdscgi.exe CGI";
 summary["francais"] = "Vérifie la présence de ppdscgi.exe";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
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
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"ppdscgi.exe", port:port);
if(res)security_warning(port);
