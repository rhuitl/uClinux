#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10618);
 script_bugtraq_id(2381);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2001-0302");
 
 name["english"] = "Pi3Web tstisap.dll overflow";
 name["francais"] = "Pi3Web tstisap.dll overflow";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The '/isapi/tstisapi.dll' cgi is installed. This CGI has
a well known security flaw that lets anyone execute arbitrary
commands with the privileges of the http service.

Solution : remove it from /isapi.

Risk factor : High";


 desc["francais"] = "Le cgi '/isapi/tstisapi.dll' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci.

Solution : retirez-le de /isapi.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /isapi/tstisapi.dll";
 summary["francais"] = "Vérifie la présence de /isapi/tstisapi.dll";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if ( "Pi3Web/" >!< banner ) exit(0);

soc = http_open_socket(port);

if(soc)
{
 req = http_get(item:"/isapi/tstisapi.dll",
		port:port);

 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("SERVER_SOFTWARE=Pi3Web/1.0.1" >< r)security_hole(port);
}
