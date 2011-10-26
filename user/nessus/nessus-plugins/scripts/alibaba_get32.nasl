#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10011);
 script_bugtraq_id(770);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-1999-0885");
 
 name["english"] = "get32.exe vulnerability";
 name["francais"] = "get32.exe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'get32.exe' CGI script is installed on this 
 machine. This CGI has a well known security flaw that allows an 
 attacker to execute arbitrary commands on the remote system with 
 the privileges of the HTTP daemon (typically root or nobody).

Solution : Remove the 'get32.exe' script from your web server's 
CGI directory (usually cgi-bin/)..

Risk factor : High";


 desc["francais"] = "Le cgi 'get32.exe' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
executer des commandes arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/get32.exe";
 summary["francais"] = "Vérifie la présence de /cgi-bin/get32.exe";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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
res = is_cgi_installed_ka(item:"get32.exe", port:port);
if( res )
{
 security_hole(port);
}
