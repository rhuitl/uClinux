#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10071);
 script_version ("$Revision: 1.17 $");
 
 name["english"] = "Finger cgi";
 name["francais"] = "Finger cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'finger' cgi is installed. It is usually
not a good idea to have such a service installed, since
it usually gives more troubles than anything else. 

Double check that you really want to have this
service installed.

Solution : remove it from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Le cgi 'finger' est installé. Ce n'est
générallement pas une bonne idée d'avoir un service
'finger' en accès libre, car cela cause plus de
problèmes qu'autre chose.

Vérifiez donc que vous voulez réellement avoir
ce service installé.

Solution : enlevez le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/finger";
 summary["francais"] = "Vérifie la présence de /cgi-bin/finger";
 
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

res = is_cgi_installed_ka(port:port, item:"finger");
if(res)
{
 security_warning(port);
}
