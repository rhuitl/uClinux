#
# Copyright 2000 by Renaud Deraison <deraison@cvs.nessus.org>
#

if(description)
{
 script_id(10340);
 script_bugtraq_id(1036);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0192");
 
 name["english"] = "rpm_query CGI";
 name["francais"] = "CGI rpm_query";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The rpm_query CGI is installed. 

This CGI allows anyone who can connect to this
web server to obtain the list of the installed
RPMs.

This allows an attacker to determine the version
number of your installed services, hence making
their attacks more accurate.

Solution : remove this CGI from cgi-bin/
Risk factor : Low";

 desc["francais"] = "
Le CGI rpm_query est installé. 

Celui-ci permet à n'importe qui en mesure
de se connecter à ce serveur d'obtenir
la liste des RPMs installés.

Ce problème permet à des pirates de déterminer
la version des services que vous faites tourner,
ce qui rend leurs attaques d'autant plus
efficaces.

Solution : retirez ce CGI de /cgi-bin
Facteur de risque : Faible";

 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "checks for rpm_query";
 summary["francais"] = "teste la présence de rpm_query";
 
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"rpm_query", port:port);
if(res)security_warning(port);
