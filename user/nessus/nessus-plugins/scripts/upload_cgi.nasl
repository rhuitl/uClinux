#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10290);
 script_version ("$Revision: 1.18 $");
 
 name["english"] = "Upload cgi";
 name["francais"] = "cgi upload";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'upload.cgi' cgi is installed. This CGI has
a well known security flaw that lets anyone upload arbitrary
files on the remote web server.

Solution : remove it from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Le cgi 'upload.cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe d'uploader
des fichiers arbitraires sur le serveur web, tels que des programmes,
qui seront ensuite executés par d'autres moyens.

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/upload.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/upload.cgi";
 
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

exit(0); # So many 'upload.cgi' out there that this does not make sense...
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"upload.cgi", port:port);
if(res)security_warning(port);
