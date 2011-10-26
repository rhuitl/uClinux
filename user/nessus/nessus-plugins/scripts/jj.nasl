#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10131);
 script_bugtraq_id(2002);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-0260");
 name["english"] = "jj cgi";
 name["francais"] = "jj cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'jj' CGI is installed. This CGI has
a well known security flaw that lets an attacker execute arbitrary
commands with the privileges of the http daemon (usually root or nobody).

Solution : Remove it from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Le cgi 'jj' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/jj";
 summary["francais"] = "Vérifie la présence de /cgi-bin/jj";
 
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

res = is_cgi_installed_ka(item:"jj", port:port);
if(res)security_hole(port);

