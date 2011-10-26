#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10507);
 script_bugtraq_id(1459);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0629");
 name["english"] = "Sun's Java Web Server remote command execution";
 name["francais"] = "Sun's Java Web Server remote command execution";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'bboard' servlet is installed in 
 /servlet/sunexamples.BBoardServlet. This servlet has
a well known security flaw that lets anyone execute arbitrary
commands with the privileges of the http daemon (root or nobody).

Solution : remove it.

Risk factor : High";


 desc["francais"] = "Le servlet 'bboard' est installé dans
/servlet/sunexamples.BBoardServlet.
Celui-ci possède un problème de sécurité bien connu qui permet à n'importe 
qui de faire executer des commandes arbitraires au daemon http, avec les
privilèges de celui-ci (root ou nobody). 

Solution : retirez-le.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /servlet/sunexamples.BBoardServlet";
 summary["francais"] = "Vérifie la présence de /servlet/sunexamples.BBoardServlet";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
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
res = is_cgi_installed_ka(item:"/servlet/nessus." + rand(), port:port);
if ( res ) exit(0);

res = is_cgi_installed_ka(item:"/servlet/sunexamples.BBoardServlet", port:port);
if( res )security_hole(port);

